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
    /// How long the server waits before answering.
    delay: Duration,
}

fn ok(body: Vec<u8>) -> Response {
    Response {
        status: 200,
        headers: Vec::new(),
        body,
        delay: Duration::ZERO,
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
                    delay: Duration::ZERO,
                });
                thread::sleep(response.delay);
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
        lock_wait: Duration::from_secs(60),
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
        .fetch(&[ecosystem], || at(1_000))
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
        .fetch(&["crates.io", "npm"], || at(1_000))
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
        .fetch(&["crates.io"], || at(1_000))
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
        .fetch(&["crates.io"], || at(1_000))
        .expect("the archive is fetched");

    let second = archives(cache.path(), &server, Refresh::IfMissing)
        .fetch(&["crates.io"], || at(5_000))
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
        .fetch(&["crates.io"], || at(1_000))
        .expect("the archive is fetched");
    server.route("/crates.io/all.zip", ok(npm_archive()));

    let snapshots = archives(cache.path(), &server, Refresh::Always)
        .fetch(&["crates.io"], || at(2_000))
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
        .fetch(&["crates.io"], || at(1_000))
        .expect("the archive is fetched");
    server.route(
        "/crates.io/all.zip",
        Response {
            status: 503,
            headers: Vec::new(),
            body: b"unavailable".to_vec(),
            delay: Duration::ZERO,
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
        .fetch(&["crates.io"], || at(3_000))
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
        .fetch(&["crates.io"], || at(1_000))
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
        .fetch(&["crates.io"], || at(3_000))
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
        lock_wait: Duration::from_secs(60),
    };

    let error = unreachable
        .fetch(&["crates.io"], || at(1_000))
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
            .fetch(&[name], || at(1_000))
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

// spec: OSR-H4, OSR-12, OSR-15
#[test]
fn a_cache_is_read_offline_without_a_request() {
    let cache = TempDir::new().expect("a cache");
    let server = Server::new();
    server.route(
        "/crates.io/all.zip",
        Response {
            headers: vec![("Last-Modified", "Wed, 11 Nov 2026 08:00:00 GMT")],
            ..ok(crates_io_archive())
        },
    );
    let filled = archives(cache.path(), &server, Refresh::IfMissing)
        .fetch(&["crates.io"], || at(1_000))
        .expect("the archive is fetched");

    let read = archives(cache.path(), &server, Refresh::Offline)
        .fetch(&["crates.io"], || at(9_000))
        .expect("the cache is read");

    assert_eq!(server.requests().len(), 1);
    assert_eq!(read, filled);
}

// spec: OSR-12, OSR-13, OSR-18
#[test]
fn an_ecosystem_not_cached_fails_offline_without_a_request() {
    let cache = TempDir::new().expect("a cache");
    let server = Server::new();
    server.route("/npm/all.zip", ok(npm_archive()));

    let error = fetch_error(cache.path(), &server, Refresh::Offline, "npm");

    assert_eq!(error.ecosystem, "npm");
    assert_eq!(error.cause, FetchCause::NotCached);
    assert!(error.to_string().contains("not cached"), "{error}");
    assert!(error.to_string().contains("npm"), "{error}");
    assert_eq!(server.requests(), Vec::<String>::new());
}

// spec: OSR-13
#[test]
fn a_snapshot_older_than_the_age_is_downloaded_again() {
    let hour = Duration::from_secs(3_600);
    let cache = TempDir::new().expect("a cache");
    let server = Server::new();
    server.route("/crates.io/all.zip", ok(crates_io_archive()));
    archives(cache.path(), &server, Refresh::IfMissing)
        .fetch(&["crates.io"], || at(10_000))
        .expect("the archive is fetched");
    let two_hours_later = at(10_000) + 2 * hour;

    let kept = archives(cache.path(), &server, Refresh::OlderThan(24 * hour))
        .fetch(&["crates.io"], || two_hours_later)
        .expect("the snapshot is read");
    assert_eq!(server.requests().len(), 1);
    assert_eq!(kept[0].freshness.downloaded_at, at(10_000));

    let renewed = archives(cache.path(), &server, Refresh::OlderThan(hour))
        .fetch(&["crates.io"], || two_hours_later)
        .expect("the archive is fetched again");
    assert_eq!(server.requests().len(), 2);
    assert_eq!(renewed[0].freshness.downloaded_at, two_hours_later);
}

// spec: OSR-13
#[test]
fn an_empty_cache_is_filled_under_older_than() {
    let cache = TempDir::new().expect("a cache");
    let server = Server::new();
    server.route("/crates.io/all.zip", ok(crates_io_archive()));

    let snapshots = archives(
        cache.path(),
        &server,
        Refresh::OlderThan(Duration::from_secs(60)),
    )
    .fetch(&["crates.io"], || at(1_000))
    .expect("the archive is fetched");

    assert_eq!(server.requests().len(), 1);
    assert_eq!(ids(&snapshots[0]), ["RUSTSEC-2020-0071"]);
}

// spec: OSR-13
#[test]
fn a_snapshot_dated_after_now_is_not_downloaded_again() {
    let cache = TempDir::new().expect("a cache");
    let server = Server::new();
    server.route("/crates.io/all.zip", ok(crates_io_archive()));
    archives(cache.path(), &server, Refresh::IfMissing)
        .fetch(&["crates.io"], || at(5_000))
        .expect("the archive is fetched");

    // A clock set back: the snapshot is not older than the age.
    archives(
        cache.path(),
        &server,
        Refresh::OlderThan(Duration::from_secs(60)),
    )
    .fetch(&["crates.io"], || at(1_000))
    .expect("the snapshot is read");

    assert_eq!(server.requests().len(), 1);
}

// spec: OSR-13
#[test]
fn a_snapshot_whose_freshness_cannot_be_read_is_downloaded_again() {
    let cache = TempDir::new().expect("a cache");
    let server = Server::new();
    server.route("/crates.io/all.zip", ok(crates_io_archive()));
    archives(cache.path(), &server, Refresh::IfMissing)
        .fetch(&["crates.io"], || at(1_000))
        .expect("the archive is fetched");
    fs::write(
        cache.path().join("crates.io/forewarn-freshness"),
        "{ truncated",
    )
    .expect("the freshness is damaged");

    let snapshots = archives(cache.path(), &server, Refresh::IfMissing)
        .fetch(&["crates.io"], || at(2_000))
        .expect("the archive is fetched again");

    assert_eq!(server.requests().len(), 2);
    assert_eq!(snapshots[0].freshness.downloaded_at, at(2_000));
}

// spec: OSR-16
#[test]
fn a_snapshot_left_aside_by_a_stopped_run_is_put_back() {
    let cache = TempDir::new().expect("a cache");
    let server = Server::new();
    server.route("/crates.io/all.zip", ok(crates_io_archive()));
    let filled = archives(cache.path(), &server, Refresh::IfMissing)
        .fetch(&["crates.io"], || at(1_000))
        .expect("the archive is fetched");
    // A run stopped between moving the snapshot aside and putting the new one in place.
    fs::rename(
        cache.path().join("crates.io"),
        cache.path().join(".former-crates.io"),
    )
    .expect("moved aside");

    let read = archives(cache.path(), &server, Refresh::Offline)
        .fetch(&["crates.io"], || at(2_000))
        .expect("the snapshot is put back");

    assert_eq!(read, filled);
}

// spec: OSR-16
#[test]
fn what_a_stopped_download_left_is_cleared() {
    let cache = TempDir::new().expect("a cache");
    let server = Server::new();
    server.route("/crates.io/all.zip", ok(crates_io_archive()));
    fs::create_dir(cache.path().join(".staging-crates.io")).expect("a stale staging");
    fs::write(
        cache
            .path()
            .join(".staging-crates.io/GHSA-35jh-r3h4-6jhm.json"),
        fixture("GHSA-35jh-r3h4-6jhm.json"),
    )
    .expect("a stale record");
    fs::write(cache.path().join(".download-crates.io"), "partial").expect("a stale download");

    let snapshots = archives(cache.path(), &server, Refresh::IfMissing)
        .fetch(&["crates.io"], || at(1_000))
        .expect("the archive is fetched");

    assert_eq!(ids(&snapshots[0]), ["RUSTSEC-2020-0071"]);
    let mut left: Vec<_> = fs::read_dir(cache.path())
        .expect("the cache is listed")
        .map(|entry| entry.expect("an entry").file_name())
        .collect();
    left.sort();
    assert_eq!(left, [".lock-crates.io", "crates.io"]);
}

// spec: OSR-11
#[test]
fn each_download_records_the_time_it_started() {
    let cache = TempDir::new().expect("a cache");
    let server = Server::new();
    server.route("/crates.io/all.zip", ok(crates_io_archive()));
    server.route("/npm/all.zip", ok(npm_archive()));
    let ticks = std::cell::Cell::new(0);
    let clock = || {
        ticks.set(ticks.get() + 1);
        at(1_000 * ticks.get())
    };

    let snapshots = archives(cache.path(), &server, Refresh::IfMissing)
        .fetch(&["crates.io", "npm"], clock)
        .expect("the archives are fetched");

    assert_eq!(snapshots[0].freshness.downloaded_at, at(1_000));
    assert_eq!(snapshots[1].freshness.downloaded_at, at(2_000));
}

/// Locks a lock file as another run would, until the returned file is dropped.
fn lock_file(path: &Path) -> fs::File {
    let file = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(path)
        .expect("the lock file");
    file.lock().expect("the lock");
    file
}

/// Locks the lock file of an ecosystem as another run would, until the returned file is dropped.
fn hold_lock(cache: &Path, ecosystem: &str) -> fs::File {
    fs::create_dir_all(cache).expect("the cache");
    lock_file(&cache.join(format!(".lock-{ecosystem}")))
}

/// A child process, killed when dropped, so that a failed test never leaves it holding a lock.
struct Child(std::process::Child);

impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Waits until the server has received `count` requests.
fn wait_for_requests(server: &Server, count: usize) {
    for _ in 0..500 {
        if server.requests().len() >= count {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("{count} requests expected, got {:?}", server.requests());
}

// spec: OSR-H5, OSR-19
#[test]
fn a_second_run_waits_for_the_first_and_reads_its_snapshot() {
    let cache = TempDir::new().expect("a cache");
    let server = Server::new();
    server.route(
        "/crates.io/all.zip",
        Response {
            delay: Duration::from_millis(500),
            ..ok(crates_io_archive())
        },
    );
    let (first, second) = (
        archives(cache.path(), &server, Refresh::IfMissing),
        archives(cache.path(), &server, Refresh::IfMissing),
    );

    let first = thread::spawn(move || first.fetch(&["crates.io"], || at(1_000)));
    wait_for_requests(&server, 1);
    let second = thread::spawn(move || second.fetch(&["crates.io"], || at(2_000)));
    let first = first.join().expect("the first run").expect("fetched");
    let second = second.join().expect("the second run").expect("fetched");

    assert_eq!(server.requests(), ["GET /crates.io/all.zip"]);
    assert_eq!(second, first);
}

// spec: OSR-20
#[test]
fn runs_fetching_different_ecosystems_do_not_wait_for_each_other() {
    let cache = TempDir::new().expect("a cache");
    let server = Server::new();
    server.route("/npm/all.zip", ok(npm_archive()));
    let _crates_io = hold_lock(cache.path(), "crates.io");
    let npm = Archives {
        lock_wait: Duration::ZERO,
        ..archives(cache.path(), &server, Refresh::IfMissing)
    };

    let snapshots = npm
        .fetch(&["npm"], || at(1_000))
        .expect("npm does not wait for crates.io");

    assert_eq!(ids(&snapshots[0]), ["GHSA-35jh-r3h4-6jhm"]);
}

/// Takes the shared lock of an ecosystem as a run reading its snapshot would, until the returned file is dropped.
fn hold_shared_lock(cache: &Path, ecosystem: &str) -> fs::File {
    let file = fs::File::open(cache.join(format!(".lock-{ecosystem}"))).expect("the lock file");
    file.lock_shared().expect("the shared lock");
    file
}

// spec: OSR-32
#[test]
fn runs_reading_the_same_snapshot_do_not_wait_for_each_other() {
    let cache = TempDir::new().expect("a cache");
    let server = Server::new();
    server.route("/crates.io/all.zip", ok(crates_io_archive()));
    let filled = archives(cache.path(), &server, Refresh::IfMissing)
        .fetch(&["crates.io"], || at(1_000))
        .expect("the archive is fetched");
    let _reading = hold_shared_lock(cache.path(), "crates.io");
    let second = Archives {
        lock_wait: Duration::ZERO,
        ..archives(cache.path(), &server, Refresh::IfMissing)
    };

    let read = second
        .fetch(&["crates.io"], || at(2_000))
        .expect("a reader does not wait for a reader");

    assert_eq!(read, filled);
    assert_eq!(server.requests().len(), 1);
}

// spec: OSR-33, OSR-22
#[test]
fn a_download_waits_for_the_runs_reading_the_snapshot() {
    let cache = TempDir::new().expect("a cache");
    let server = Server::new();
    server.route("/crates.io/all.zip", ok(crates_io_archive()));
    let before = archives(cache.path(), &server, Refresh::IfMissing)
        .fetch(&["crates.io"], || at(1_000))
        .expect("the archive is fetched");
    let reading = hold_shared_lock(cache.path(), "crates.io");
    let downloading = Archives {
        lock_wait: Duration::from_millis(300),
        ..archives(cache.path(), &server, Refresh::Always)
    };

    let error = downloading
        .fetch(&["crates.io"], || at(2_000))
        .expect_err("the download waits for the reader");

    assert_eq!(
        error.cause,
        FetchCause::Locked {
            waited: Duration::from_millis(300)
        }
    );
    assert_eq!(server.requests().len(), 1);
    drop(reading);
    let after = archives(cache.path(), &server, Refresh::Offline)
        .fetch(&["crates.io"], || at(3_000))
        .expect("the snapshot is kept");
    assert_eq!(after, before);
}

// spec: OSR-33
#[test]
fn putting_back_a_snapshot_waits_for_the_runs_reading() {
    let cache = TempDir::new().expect("a cache");
    let server = Server::new();
    server.route("/crates.io/all.zip", ok(crates_io_archive()));
    archives(cache.path(), &server, Refresh::IfMissing)
        .fetch(&["crates.io"], || at(1_000))
        .expect("the archive is fetched");
    fs::rename(
        cache.path().join("crates.io"),
        cache.path().join(".former-crates.io"),
    )
    .expect("moved aside");
    let _reading = hold_shared_lock(cache.path(), "crates.io");
    let restoring = Archives {
        lock_wait: Duration::from_millis(300),
        ..archives(cache.path(), &server, Refresh::IfMissing)
    };

    let error = restoring
        .fetch(&["crates.io"], || at(2_000))
        .expect_err("putting back waits for the reader");

    assert!(
        matches!(error.cause, FetchCause::Locked { .. }),
        "{error:?}"
    );
    assert!(cache.path().join(".former-crates.io").is_dir());
}

// spec: OSR-19, OSR-13
#[test]
fn two_runs_finding_the_snapshot_too_old_download_it_once() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let cache = TempDir::new().expect("a cache");
    let server = Server::new();
    server.route("/crates.io/all.zip", ok(crates_io_archive()));
    archives(cache.path(), &server, Refresh::IfMissing)
        .fetch(&["crates.io"], || at(0))
        .expect("the archive is fetched");
    // Held until both runs have read the old freshness: each then needs the exclusive lock to download.
    let reading = hold_shared_lock(cache.path(), "crates.io");
    let readings = Arc::new(AtomicUsize::new(0));
    let runs: Vec<_> = (0..2)
        .map(|_| {
            let run = archives(
                cache.path(),
                &server,
                Refresh::OlderThan(Duration::from_secs(3_600)),
            );
            let readings = Arc::clone(&readings);
            thread::spawn(move || {
                run.fetch(&["crates.io"], || {
                    readings.fetch_add(1, Ordering::SeqCst);
                    at(7_200)
                })
            })
        })
        .collect();
    for _ in 0..500 {
        if readings.load(Ordering::SeqCst) >= 2 {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        readings.load(Ordering::SeqCst) >= 2,
        "both runs read the freshness"
    );
    drop(reading);

    let snapshots: Vec<_> = runs
        .into_iter()
        .map(|run| run.join().expect("the run").expect("fetched"))
        .collect();

    assert_eq!(server.requests().len(), 2);
    assert_eq!(snapshots[0], snapshots[1]);
    assert_eq!(snapshots[0][0].freshness.downloaded_at, at(7_200));
}

/// The variable naming the lock file the helper process below locks before it waits to be killed.
const HOLDER_LOCK: &str = "FOREWARN_TEST_HOLD_LOCK";

/// Not a test of its own: run as a child process by the test of OSR-21, it holds a lock until it is killed.
#[test]
fn lock_holder_process() {
    let Some(path) = std::env::var_os(HOLDER_LOCK) else {
        return;
    };
    let _file = lock_file(Path::new(&path));
    println!("locked");
    std::io::stdout().flush().expect("flushed");
    thread::sleep(Duration::from_secs(600));
}

// spec: OSR-21
#[test]
fn a_lock_left_by_a_killed_run_does_not_block() {
    let cache = TempDir::new().expect("a cache");
    let server = Server::new();
    server.route("/crates.io/all.zip", ok(crates_io_archive()));
    let mut holder = Child(
        std::process::Command::new(std::env::current_exe().expect("the test binary"))
            .args([
                "--exact",
                "lock_holder_process",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(HOLDER_LOCK, cache.path().join(".lock-crates.io"))
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("the holder starts"),
    );
    let mut output = std::io::BufReader::new(holder.0.stdout.take().expect("its output"));
    let mut line = String::new();
    while !line.contains("locked") {
        line.clear();
        assert_ne!(
            std::io::BufRead::read_line(&mut output, &mut line).expect("a line"),
            0,
            "the holder ended before locking"
        );
    }
    drop(holder);
    // A short wait: Windows releases the locks of an ended process asynchronously.
    let after = Archives {
        lock_wait: Duration::from_secs(5),
        ..archives(cache.path(), &server, Refresh::IfMissing)
    };

    let snapshots = after
        .fetch(&["crates.io"], || at(1_000))
        .expect("the lock of the killed run does not block");

    assert_eq!(ids(&snapshots[0]), ["RUSTSEC-2020-0071"]);
}

// spec: OSR-22, OSR-18
#[test]
fn a_run_waiting_longer_than_its_bound_fails_with_cache_locked() {
    let cache = TempDir::new().expect("a cache");
    let server = Server::new();
    server.route("/crates.io/all.zip", ok(crates_io_archive()));
    let before = archives(cache.path(), &server, Refresh::IfMissing)
        .fetch(&["crates.io"], || at(1_000))
        .expect("the archive is fetched");
    let held = hold_lock(cache.path(), "crates.io");
    let waiting = Archives {
        lock_wait: Duration::from_millis(300),
        ..archives(cache.path(), &server, Refresh::Always)
    };

    let error = waiting
        .fetch(&["crates.io"], || at(2_000))
        .expect_err("the fetch gives up");

    assert_eq!(
        error,
        FetchError {
            ecosystem: "crates.io".to_owned(),
            cause: FetchCause::Locked {
                waited: Duration::from_millis(300)
            },
        }
    );
    assert!(
        error.to_string().contains("cache locked by another run"),
        "{error}"
    );
    assert_eq!(server.requests().len(), 1);
    drop(held);
    let after = archives(cache.path(), &server, Refresh::Offline)
        .fetch(&["crates.io"], || at(3_000))
        .expect("the snapshot is kept");
    assert_eq!(after, before);
}

// spec: OSR-22
#[test]
fn the_default_wait_is_40_minutes() {
    let archives = Archives::new(PathBuf::from("cache"), Refresh::IfMissing);

    assert_eq!(archives.lock_wait, Duration::from_secs(40 * 60));
}

// spec: OSR-23
#[cfg(unix)]
#[test]
fn an_offline_run_reads_a_cache_it_cannot_write_in() {
    use std::os::unix::fs::PermissionsExt;

    let cache = TempDir::new().expect("a cache");
    let server = Server::new();
    server.route("/crates.io/all.zip", ok(crates_io_archive()));
    let filled = archives(cache.path(), &server, Refresh::IfMissing)
        .fetch(&["crates.io"], || at(1_000))
        .expect("the archive is fetched");
    fs::remove_file(cache.path().join(".lock-crates.io")).expect("no lock file");
    fs::set_permissions(cache.path(), fs::Permissions::from_mode(0o555)).expect("read-only");

    let read =
        archives(cache.path(), &server, Refresh::Offline).fetch(&["crates.io"], || at(2_000));

    fs::set_permissions(cache.path(), fs::Permissions::from_mode(0o755)).expect("writable");
    assert_eq!(read.expect("the snapshot is read"), filled);
}

// spec: OSR-19
#[cfg(unix)]
#[test]
fn a_lock_file_the_run_can_only_read_still_locks() {
    use std::os::unix::fs::PermissionsExt;

    let cache = TempDir::new().expect("a cache");
    let server = Server::new();
    server.route("/crates.io/all.zip", ok(crates_io_archive()));
    // Created by another user of a shared cache, with a umask leaving others read only.
    let lock = cache.path().join(".lock-crates.io");
    fs::write(&lock, "").expect("a lock file");
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o444)).expect("read-only");
    let held = lock_file_read_only(&lock);
    let waiting = Archives {
        lock_wait: Duration::from_millis(300),
        ..archives(cache.path(), &server, Refresh::IfMissing)
    };

    let error = waiting
        .fetch(&["crates.io"], || at(1_000))
        .expect_err("the fetch waits for the lock");
    drop(held);
    let snapshots = archives(cache.path(), &server, Refresh::IfMissing)
        .fetch(&["crates.io"], || at(1_000))
        .expect("the archive is fetched once the lock is released");

    assert!(
        matches!(error.cause, FetchCause::Locked { .. }),
        "{error:?}"
    );
    assert_eq!(ids(&snapshots[0]), ["RUSTSEC-2020-0071"]);
}

#[cfg(unix)]
fn lock_file_read_only(path: &Path) -> fs::File {
    let file = fs::File::open(path).expect("the lock file");
    file.lock().expect("the lock");
    file
}

/// The record file of the cached `crates.io` snapshot.
fn crates_io_record(cache: &Path) -> PathBuf {
    cache.join("crates.io/RUSTSEC-2020-0071.json")
}

/// Fills a cache with the `crates.io` snapshot, downloaded at 1,000 s, through a server that keeps serving it.
fn cached_crates_io(cache: &Path) -> Server {
    let server = Server::new();
    server.route("/crates.io/all.zip", ok(crates_io_archive()));
    archives(cache, &server, Refresh::IfMissing)
        .fetch(&["crates.io"], || at(1_000))
        .expect("the archive is fetched");
    server
}

/// A change of a snapshot outside forewarn: the words of its error, the change, the file the error names.
type Damaging = (&'static str, fn(&Path), &'static str);

/// The ways a snapshot is changed outside forewarn that its files tell apart.
fn damages() -> [Damaging; 3] {
    [
        (
            "removed",
            |cache| fs::remove_file(crates_io_record(cache)).expect("the record is removed"),
            "RUSTSEC-2020-0071.json",
        ),
        (
            "another size",
            |cache| {
                fs::write(crates_io_record(cache), "{ truncated").expect("the record is truncated");
            },
            "RUSTSEC-2020-0071.json",
        ),
        (
            "added",
            |cache| {
                fs::write(
                    cache.join("crates.io/extra.json"),
                    fixture("RUSTSEC-2020-0071.json"),
                )
                .expect("a record is added");
            },
            "extra.json",
        ),
    ]
}

// spec: OSR-38
#[test]
fn a_snapshot_whose_files_differ_from_its_download_is_downloaded_again_once() {
    for (damage, apply, _) in damages() {
        let cache = TempDir::new().expect("a cache");
        let server = cached_crates_io(cache.path());
        apply(cache.path());

        let snapshots = archives(cache.path(), &server, Refresh::IfMissing)
            .fetch(&["crates.io"], || at(2_000))
            .expect("the archive is fetched again");

        assert_eq!(server.requests().len(), 2, "{damage}");
        assert_eq!(ids(&snapshots[0]), ["RUSTSEC-2020-0071"], "{damage}");
        assert_eq!(snapshots[0].freshness.downloaded_at, at(2_000), "{damage}");
        let again = archives(cache.path(), &server, Refresh::IfMissing)
            .fetch(&["crates.io"], || at(3_000))
            .expect("the new snapshot is read");
        assert_eq!(again, snapshots, "{damage}");
        assert_eq!(server.requests().len(), 2, "{damage}");
    }
}

// spec: OSR-39, OSR-18
#[test]
fn a_snapshot_whose_files_differ_from_its_download_fails_offline_without_a_request() {
    for (damage, apply, file) in damages() {
        let cache = TempDir::new().expect("a cache");
        let server = cached_crates_io(cache.path());
        apply(cache.path());

        let error = fetch_error(cache.path(), &server, Refresh::Offline, "crates.io");

        let message = error.to_string();
        assert!(
            message.contains("damaged cached copy"),
            "{damage}: {message}"
        );
        assert!(message.contains(file), "{damage}: {message}");
        assert!(message.contains(damage), "{damage}: {message}");
        assert_eq!(server.requests().len(), 1, "{damage}");
    }
}

// spec: OSR-38, OSR-16
#[test]
fn a_damaged_snapshot_whose_download_fails_is_requested_once() {
    let cache = TempDir::new().expect("a cache");
    let server = cached_crates_io(cache.path());
    fs::remove_file(crates_io_record(cache.path())).expect("the record is removed");
    server.route(
        "/crates.io/all.zip",
        Response {
            status: 503,
            headers: Vec::new(),
            body: b"unavailable".to_vec(),
            delay: Duration::ZERO,
        },
    );

    let error = fetch_error(cache.path(), &server, Refresh::IfMissing, "crates.io");

    assert!(error.to_string().contains("cannot download"), "{error}");
    assert_eq!(server.requests().len(), 2);
}

// spec: OSR-40
#[test]
fn a_snapshot_of_its_download_whose_records_cannot_be_read_fails_without_a_request() {
    let cache = TempDir::new().expect("a cache");
    let server = cached_crates_io(cache.path());
    let size = fs::metadata(crates_io_record(cache.path()))
        .expect("the record")
        .len();
    fs::write(
        crates_io_record(cache.path()),
        vec![b'x'; usize::try_from(size).expect("a size")],
    )
    .expect("the record is overwritten");

    let error = fetch_error(cache.path(), &server, Refresh::IfMissing, "crates.io");

    assert!(error.to_string().contains("not JSON"), "{error}");
    assert!(
        error.to_string().contains("RUSTSEC-2020-0071.json"),
        "{error}"
    );
    assert_eq!(server.requests().len(), 1);
}

// spec: OSR-40
#[cfg(unix)]
#[test]
fn a_snapshot_of_its_download_that_cannot_be_opened_fails_without_a_request() {
    use std::os::unix::fs::PermissionsExt;

    let cache = TempDir::new().expect("a cache");
    let server = cached_crates_io(cache.path());
    let record = crates_io_record(cache.path());
    fs::set_permissions(&record, fs::Permissions::from_mode(0o000)).expect("the mode");
    if fs::read(&record).is_ok() {
        // A user who reads any file (root) cannot see the error.
        return;
    }

    let error = fetch_error(cache.path(), &server, Refresh::IfMissing, "crates.io");

    assert!(
        error
            .to_string()
            .to_lowercase()
            .contains("permission denied"),
        "{error}"
    );
    assert_eq!(server.requests().len(), 1);
}

/// Rewrites the freshness of the cached `crates.io` snapshot as an earlier forewarn wrote it, with no list of files.
fn forget_the_files_of_crates_io(cache: &Path) {
    let path = cache.join("crates.io/forewarn-freshness");
    let mut freshness: serde_json::Map<String, serde_json::Value> =
        serde_json::from_slice(&fs::read(&path).expect("the freshness")).expect("a JSON object");
    assert!(
        freshness.remove("files").is_some(),
        "the freshness lists the files"
    );
    fs::write(&path, serde_json::to_vec(&freshness).expect("JSON")).expect("the freshness");
}

// spec: OSR-41
#[test]
fn a_snapshot_whose_freshness_names_no_files_is_downloaded_again_once() {
    let cache = TempDir::new().expect("a cache");
    let server = cached_crates_io(cache.path());
    forget_the_files_of_crates_io(cache.path());

    let snapshots = archives(cache.path(), &server, Refresh::IfMissing)
        .fetch(&["crates.io"], || at(2_000))
        .expect("the archive is fetched again");

    assert_eq!(server.requests().len(), 2);
    assert_eq!(snapshots[0].freshness.downloaded_at, at(2_000));
    archives(cache.path(), &server, Refresh::IfMissing)
        .fetch(&["crates.io"], || at(3_000))
        .expect("the new snapshot is read");
    assert_eq!(server.requests().len(), 2);
}

// spec: OSR-41
#[test]
fn a_snapshot_whose_freshness_names_no_files_is_read_offline() {
    let cache = TempDir::new().expect("a cache");
    let server = cached_crates_io(cache.path());
    forget_the_files_of_crates_io(cache.path());

    let snapshots = archives(cache.path(), &server, Refresh::Offline)
        .fetch(&["crates.io"], || at(2_000))
        .expect("the snapshot is read");

    assert_eq!(ids(&snapshots[0]), ["RUSTSEC-2020-0071"]);
    assert_eq!(snapshots[0].freshness.downloaded_at, at(1_000));
    assert_eq!(server.requests().len(), 1);
}
