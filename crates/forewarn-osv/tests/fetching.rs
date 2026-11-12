//! Fetching the OSV archive of each ecosystem into a cache (`specs/osv-reading.md`), against a loopback HTTP server:
//! no test needs the network.

use std::collections::HashMap;
use std::fs;
use std::io::{Cursor, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime};

use forewarn_osv::fetch::{Archives, FetchCause, FetchError, Refresh, Snapshot};
use forewarn_osv::{Cause, ReadError};
use tempfile::TempDir;
use zip::ZipWriter;
use zip::write::SimpleFileOptions;

/// A response of the loopback server: status, headers, body.
#[derive(Clone)]
struct Response {
    status: u16,
    headers: Vec<(&'static str, &'static str)>,
    body: Vec<u8>,
}

fn ok(body: Vec<u8>) -> Response {
    Response {
        status: 200,
        headers: Vec::new(),
        body,
    }
}

/// A loopback HTTP server answering each path from a table, 404 otherwise, and recording each request line.
struct Server {
    base: String,
    requests: Arc<Mutex<Vec<String>>>,
    routes: Arc<Mutex<HashMap<String, Response>>>,
}

impl Server {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        let base = format!("http://{}", listener.local_addr().expect("an address"));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let routes: Arc<Mutex<HashMap<String, Response>>> = Arc::default();
        let (seen, table) = (Arc::clone(&requests), Arc::clone(&routes));
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let head = read_head(&mut stream);
                let line = head.lines().next().unwrap_or_default().to_owned();
                let has_body = head.lines().any(|header| {
                    let header = header.to_ascii_lowercase();
                    header.starts_with("content-length:")
                        || header.starts_with("transfer-encoding:")
                });
                let path = line.split(' ').nth(1).unwrap_or_default().to_owned();
                let method = line.split(' ').next().unwrap_or_default();
                seen.lock().expect("the requests").push(format!(
                    "{method} {path}{}",
                    if has_body { " with a body" } else { "" }
                ));
                let response = table.lock().expect("the routes").get(&path).cloned();
                let response = response.unwrap_or(Response {
                    status: 404,
                    headers: Vec::new(),
                    body: b"not found".to_vec(),
                });
                let mut reply = format!(
                    "HTTP/1.1 {} X\r\nContent-Length: {}\r\nConnection: close\r\n",
                    response.status,
                    response.body.len()
                )
                .into_bytes();
                for (name, value) in &response.headers {
                    let _ = write!(reply, "{name}: {value}\r\n");
                }
                reply.extend_from_slice(b"\r\n");
                let _ = stream.write_all(&reply);
                let _ = stream.write_all(&response.body);
            }
        });
        Self {
            base,
            requests,
            routes,
        }
    }

    fn route(&self, path: &str, response: Response) {
        self.routes
            .lock()
            .expect("the routes")
            .insert(path.to_owned(), response);
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().expect("the requests").clone()
    }
}

fn read_head(stream: &mut impl Read) -> String {
    let mut head = Vec::new();
    let mut byte = [0; 1];
    while !head.ends_with(b"\r\n\r\n") && stream.read(&mut byte).is_ok_and(|n| n == 1) {
        head.push(byte[0]);
    }
    String::from_utf8_lossy(&head).into_owned()
}

fn fixture(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    fs::read(path).expect("the fixture is read")
}

/// A zip archive holding these entries.
fn archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    for (name, content) in entries {
        zip.start_file(*name, SimpleFileOptions::default())
            .expect("an entry");
        zip.write_all(content).expect("its content");
    }
    zip.finish().expect("the archive").into_inner()
}

fn crates_io_archive() -> Vec<u8> {
    archive(&[("RUSTSEC-2020-0071.json", &fixture("RUSTSEC-2020-0071.json"))])
}

fn npm_archive() -> Vec<u8> {
    archive(&[(
        "GHSA-35jh-r3h4-6jhm.json",
        &fixture("GHSA-35jh-r3h4-6jhm.json"),
    )])
}

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
}

fn archives(cache: &Path, server: &Server, refresh: Refresh) -> Archives {
    Archives {
        cache: cache.to_path_buf(),
        base_url: server.base.clone(),
        refresh,
    }
}

fn ids(snapshot: &Snapshot) -> Vec<&str> {
    snapshot
        .vulnerabilities
        .iter()
        .map(|v| v.id.as_str())
        .collect()
}

fn fetch_error(cache: &Path, server: &Server, refresh: Refresh, ecosystem: &str) -> FetchError {
    archives(cache, server, refresh)
        .fetch(&[ecosystem], at(1_000))
        .expect_err("the fetch fails")
}

// spec: OSR-H3, OSR-10, OSR-11, OSR-14
#[test]
fn the_archives_of_the_ecosystems_are_downloaded_and_read_with_their_freshness() {
    let cache = TempDir::new().expect("a cache");
    let server = Server::new();
    server.route(
        "/crates.io/all.zip",
        Response {
            headers: vec![("Last-Modified", "Wed, 11 Nov 2026 08:00:00 GMT")],
            ..ok(crates_io_archive())
        },
    );
    server.route("/npm/all.zip", ok(npm_archive()));

    let snapshots = archives(cache.path(), &server, Refresh::IfMissing)
        .fetch(&["crates.io", "npm"], at(1_000))
        .expect("the archives are fetched");

    assert_eq!(
        server.requests(),
        ["GET /crates.io/all.zip", "GET /npm/all.zip"]
    );
    let [crates_io, npm] = snapshots.as_slice() else {
        panic!("two snapshots: {snapshots:?}")
    };
    assert_eq!(crates_io.ecosystem, "crates.io");
    assert_eq!(ids(crates_io), ["RUSTSEC-2020-0071"]);
    assert_eq!(crates_io.freshness.downloaded_at, at(1_000));
    assert_eq!(
        crates_io.freshness.url,
        format!("{}/crates.io/all.zip", server.base)
    );
    assert_eq!(
        crates_io.freshness.last_modified.as_deref(),
        Some("Wed, 11 Nov 2026 08:00:00 GMT")
    );
    assert_eq!(npm.ecosystem, "npm");
    assert_eq!(ids(npm), ["GHSA-35jh-r3h4-6jhm"]);
    assert_eq!(npm.freshness.last_modified, None);
}

// spec: OSR-14
#[test]
fn the_default_base_is_the_osv_bucket() {
    let archives = Archives::new(PathBuf::from("cache"), Refresh::IfMissing);

    assert_eq!(
        archives.base_url,
        "https://osv-vulnerabilities.storage.googleapis.com"
    );
}

// spec: OSR-10
#[test]
fn only_the_records_at_the_top_of_an_archive_are_read() {
    let cache = TempDir::new().expect("a cache");
    let server = Server::new();
    let record = fixture("RUSTSEC-2020-0071.json");
    server.route(
        "/crates.io/all.zip",
        ok(archive(&[
            ("RUSTSEC-2020-0071.json", &record),
            (
                "nested/GHSA-35jh-r3h4-6jhm.json",
                &fixture("GHSA-35jh-r3h4-6jhm.json"),
            ),
            ("README.txt", b"not a record"),
        ])),
    );

    let snapshots = archives(cache.path(), &server, Refresh::IfMissing)
        .fetch(&["crates.io"], at(1_000))
        .expect("the archive is fetched");

    assert_eq!(ids(&snapshots[0]), ["RUSTSEC-2020-0071"]);
}

// spec: OSR-15 (internal: the snapshot read back under `if-missing`; OSR-H4 traces it under `offline`)
#[test]
fn a_cached_snapshot_is_read_back_without_a_request() {
    let cache = TempDir::new().expect("a cache");
    let server = Server::new();
    server.route(
        "/crates.io/all.zip",
        Response {
            headers: vec![("Last-Modified", "Wed, 11 Nov 2026 08:00:00 GMT")],
            ..ok(crates_io_archive())
        },
    );
    let first = archives(cache.path(), &server, Refresh::IfMissing)
        .fetch(&["crates.io"], at(1_000))
        .expect("the archive is fetched");

    let second = archives(cache.path(), &server, Refresh::IfMissing)
        .fetch(&["crates.io"], at(5_000))
        .expect("the snapshot is read");

    assert_eq!(server.requests().len(), 1);
    assert_eq!(second, first);
}

// spec: OSR-13 (internal: the row `always`; the other rows are traced with them)
#[test]
fn the_policy_always_downloads_again() {
    let cache = TempDir::new().expect("a cache");
    let server = Server::new();
    server.route("/crates.io/all.zip", ok(crates_io_archive()));
    archives(cache.path(), &server, Refresh::Always)
        .fetch(&["crates.io"], at(1_000))
        .expect("the archive is fetched");
    server.route("/crates.io/all.zip", ok(npm_archive()));

    let snapshots = archives(cache.path(), &server, Refresh::Always)
        .fetch(&["crates.io"], at(2_000))
        .expect("the archive is fetched again");

    assert_eq!(server.requests().len(), 2);
    assert_eq!(ids(&snapshots[0]), ["GHSA-35jh-r3h4-6jhm"]);
    assert_eq!(snapshots[0].freshness.downloaded_at, at(2_000));
}

// spec: OSR-16, OSR-18
#[test]
fn a_failed_download_keeps_the_former_snapshot() {
    let cache = TempDir::new().expect("a cache");
    let server = Server::new();
    server.route("/crates.io/all.zip", ok(crates_io_archive()));
    let before = archives(cache.path(), &server, Refresh::IfMissing)
        .fetch(&["crates.io"], at(1_000))
        .expect("the archive is fetched");
    server.route(
        "/crates.io/all.zip",
        Response {
            status: 503,
            headers: Vec::new(),
            body: b"unavailable".to_vec(),
        },
    );

    let error = fetch_error(cache.path(), &server, Refresh::Always, "crates.io");

    assert_eq!(error.ecosystem, "crates.io");
    let FetchCause::Download { url, reason } = &error.cause else {
        panic!("a download error: {error:?}")
    };
    assert_eq!(url, &format!("{}/crates.io/all.zip", server.base));
    assert!(reason.contains("503"), "{reason}");
    assert!(error.to_string().contains("cannot download"), "{error}");
    let after = archives(cache.path(), &server, Refresh::IfMissing)
        .fetch(&["crates.io"], at(3_000))
        .expect("the former snapshot is read");
    assert_eq!(after, before);
}

// spec: OSR-16, OSR-18
#[test]
fn an_unreadable_record_fails_naming_its_entry_and_keeps_the_former_snapshot() {
    let cache = TempDir::new().expect("a cache");
    let server = Server::new();
    server.route("/crates.io/all.zip", ok(crates_io_archive()));
    let before = archives(cache.path(), &server, Refresh::IfMissing)
        .fetch(&["crates.io"], at(1_000))
        .expect("the archive is fetched");
    server.route(
        "/crates.io/all.zip",
        ok(archive(&[
            ("RUSTSEC-2020-0071.json", &fixture("RUSTSEC-2020-0071.json")),
            ("broken.json", b"{ not json"),
        ])),
    );

    let error = fetch_error(cache.path(), &server, Refresh::Always, "crates.io");

    let FetchCause::Record(ReadError {
        path,
        cause: Cause::NotJson(_),
    }) = &error.cause
    else {
        panic!("a record error: {error:?}")
    };
    assert_eq!(path, Path::new("broken.json"));
    assert!(error.to_string().contains("not JSON"), "{error}");
    let after = archives(cache.path(), &server, Refresh::IfMissing)
        .fetch(&["crates.io"], at(3_000))
        .expect("the former snapshot is read");
    assert_eq!(after, before);
}

// spec: OSR-18
#[test]
fn an_unreachable_server_fails_with_cannot_download() {
    let cache = TempDir::new().expect("a cache");
    let unreachable = Archives {
        cache: cache.path().to_path_buf(),
        // A port nothing listens on: the connection is refused.
        base_url: "http://127.0.0.1:1".to_owned(),
        refresh: Refresh::IfMissing,
    };

    let error = unreachable
        .fetch(&["crates.io"], at(1_000))
        .expect_err("the fetch fails");

    assert!(
        matches!(&error.cause, FetchCause::Download { url, .. } if url == "http://127.0.0.1:1/crates.io/all.zip"),
        "{error:?}"
    );
}

// spec: OSR-18
#[test]
fn a_file_that_is_not_a_zip_archive_is_refused() {
    let cache = TempDir::new().expect("a cache");
    let server = Server::new();
    server.route("/crates.io/all.zip", ok(b"<html>moved</html>".to_vec()));

    let error = fetch_error(cache.path(), &server, Refresh::IfMissing, "crates.io");

    assert!(matches!(error.cause, FetchCause::NotZip(_)), "{error:?}");
    assert!(error.to_string().contains("not a zip archive"), "{error}");
}

// spec: OSR-18
#[test]
fn an_entry_escaping_the_cache_is_refused() {
    let cache = TempDir::new().expect("a cache");
    let root = cache.path().join("cache");
    let server = Server::new();
    for name in [
        "../evil.json",
        "/evil.json",
        "a\\evil.json",
        "a/../../evil.json",
    ] {
        server.route(
            "/crates.io/all.zip",
            ok(archive(&[(name, &fixture("RUSTSEC-2020-0071.json"))])),
        );

        let error = fetch_error(&root, &server, Refresh::Always, "crates.io");

        assert_eq!(
            error.cause,
            FetchCause::UnsafeEntry(name.to_owned()),
            "{name}"
        );
        assert!(
            error.to_string().contains("unsafe archive entry"),
            "{error}"
        );
    }
    assert!(!cache.path().join("evil.json").exists());
}

// spec: OSR-17, OSR-18
#[test]
fn an_invalid_ecosystem_name_is_refused_before_any_request() {
    let cache = TempDir::new().expect("a cache");
    let server = Server::new();
    for name in ["../x", ".hidden", "", "a/b", "a b"] {
        let error = fetch_error(cache.path(), &server, Refresh::IfMissing, name);

        assert_eq!(error.cause, FetchCause::InvalidName, "{name:?}");
        assert!(
            error.to_string().contains("invalid ecosystem name"),
            "{error}"
        );
    }
    assert_eq!(server.requests(), Vec::<String>::new());
}

// spec: OSR-17
#[test]
fn the_names_osv_uses_are_accepted() {
    let cache = TempDir::new().expect("a cache");
    let server = Server::new();
    for name in [
        "crates.io",
        "PyPI",
        "Go",
        "Maven",
        "Packagist",
        "RubyGems",
        "NuGet",
        "Hex",
        "Pub",
        "npm",
        "a_b-c",
    ] {
        server.route(&format!("/{name}/all.zip"), ok(archive(&[])));

        let snapshots = archives(cache.path(), &server, Refresh::IfMissing)
            .fetch(&[name], at(1_000))
            .expect("the name is accepted");

        assert_eq!(snapshots[0].vulnerabilities, []);
    }
}

// spec: OSR-18
#[test]
fn a_cache_that_cannot_be_written_fails_with_cannot_use_the_cache() {
    let dir = TempDir::new().expect("a directory");
    let file = dir.path().join("a-file");
    fs::write(&file, "not a directory").expect("written");
    let server = Server::new();
    server.route("/crates.io/all.zip", ok(crates_io_archive()));

    let error = fetch_error(&file, &server, Refresh::IfMissing, "crates.io");

    assert!(matches!(error.cause, FetchCause::Cache(_)), "{error:?}");
    assert!(
        error.to_string().contains("cannot use the cache"),
        "{error}"
    );
}
