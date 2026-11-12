//! `forewarn match` fetching the OSV archives of the ecosystems of an SBOM into a cache (`specs/cli-match.md`),
//! against a loopback HTTP server: no test needs the network.

mod common;

use std::collections::HashMap;
use std::fs;
use std::io::{Cursor, Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::SystemTime;

use common::{Run, bom, json_report, run_with};
use serde_json::{Value, json};
use tempfile::TempDir;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use zip::ZipWriter;
use zip::write::SimpleFileOptions;

/// The archive and the `Last-Modified` the mirror serves at each path.
type Routes = Arc<Mutex<HashMap<String, (Vec<u8>, Option<&'static str>)>>>;

/// A loopback HTTP server serving each path of a table, with its `Last-Modified` when it has one, 404 otherwise, and
/// recording the path of each request.
struct Mirror {
    base: String,
    requests: Arc<Mutex<Vec<String>>>,
    routes: Routes,
}

impl Mirror {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        let base = format!("http://{}", listener.local_addr().expect("an address"));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let routes: Routes = Arc::default();
        let (seen, table) = (Arc::clone(&requests), Arc::clone(&routes));
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut head = Vec::new();
                let mut byte = [0; 1];
                while !head.ends_with(b"\r\n\r\n") && stream.read(&mut byte).is_ok_and(|n| n == 1) {
                    head.push(byte[0]);
                }
                let head = String::from_utf8_lossy(&head);
                let path = head.split(' ').nth(1).unwrap_or_default().to_owned();
                seen.lock().expect("the requests").push(path.clone());
                let route = table.lock().expect("the routes").get(&path).cloned();
                let (status, body, last_modified) = match route {
                    Some((body, last_modified)) => (200, body, last_modified),
                    None => (404, b"not found".to_vec(), None),
                };
                let mut reply = format!(
                    "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n",
                    body.len()
                );
                if let Some(value) = last_modified {
                    reply.push_str("Last-Modified: ");
                    reply.push_str(value);
                    reply.push_str("\r\n");
                }
                reply.push_str("\r\n");
                let _ = stream.write_all(reply.as_bytes());
                let _ = stream.write_all(&body);
            }
        });
        Self {
            base,
            requests,
            routes,
        }
    }

    /// Serves the archive of `ecosystem` holding these OSV fixtures.
    fn serve(&self, ecosystem: &str, fixtures: &[&str], last_modified: Option<&'static str>) {
        let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
        for name in fixtures {
            let record = fs::read(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../forewarn-osv/tests/fixtures")
                    .join(name),
            )
            .expect("the fixture is read");
            zip.start_file(*name, SimpleFileOptions::default())
                .expect("an entry");
            zip.write_all(&record).expect("its content");
        }
        let archive = zip.finish().expect("the archive").into_inner();
        self.routes
            .lock()
            .expect("the routes")
            .insert(format!("/{ecosystem}/all.zip"), (archive, last_modified));
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().expect("the requests").clone()
    }
}

const LAST_MODIFIED: &str = "Wed, 11 Nov 2026 08:00:00 GMT";

fn component(name: &str, version: &str, purl: Option<&str>) -> Value {
    let mut component = json!({"type": "library", "name": name, "version": version});
    if let Some(purl) = purl {
        component["purl"] = json!(purl);
    }
    component
}

/// `time` 0.1.43, affected by `RUSTSEC-2020-0071`, and `serde` 1.0.0.
fn crates() -> Vec<u8> {
    bom(
        "1.6",
        &json!([
            component("time", "0.1.43", Some("pkg:cargo/time@0.1.43")),
            component("serde", "1.0.0", Some("pkg:cargo/serde@1.0.0")),
        ]),
    )
}

/// A mirror serving the `crates.io` archive of `RUSTSEC-2020-0071` with a `Last-Modified`.
fn crates_io_mirror() -> Mirror {
    let mirror = Mirror::new();
    mirror.serve(
        "crates.io",
        &["RUSTSEC-2020-0071.json"],
        Some(LAST_MODIFIED),
    );
    mirror
}

fn path(path: &Path) -> &str {
    path.to_str().expect("UTF-8 path")
}

/// Runs `forewarn match` with `args` on `sbom` from standard input, the cache in `cache`, the archives from `mirror`.
fn fetch(cache: &Path, mirror: &Mirror, args: &[&str], sbom: &[u8]) -> Run {
    let mut all = vec!["match", "--cache", path(cache), "--osv-url", &mirror.base];
    all.extend_from_slice(args);
    all.push("-");
    run_with(&all, Some(sbom), &[])
}

fn osv_of(run: &Run) -> Value {
    json_report(run)["osv"].clone()
}

fn downloaded_at(run: &Run) -> OffsetDateTime {
    let text = osv_of(run)[0]["downloadedAt"]
        .as_str()
        .expect("a string")
        .to_owned();
    assert_eq!(text.len(), "2026-11-13T10:00:00Z".len(), "{text}");
    assert!(text.ends_with('Z'), "{text}");
    OffsetDateTime::parse(&text, &Rfc3339).expect("RFC 3339")
}

// spec: MCH-H2, MCH-4, MCH-5, MCH-8, MCH-9, MCH-13, MCH-16
#[test]
fn a_ci_job_fetches_the_archive_of_its_ecosystem_and_reads_the_affected_components() {
    let cache = TempDir::new().expect("a cache");
    let mirror = crates_io_mirror();
    let before = OffsetDateTime::from(SystemTime::now()).replace_nanosecond(0);
    let before = before.expect("a valid time");
    let run = fetch(
        cache.path(),
        &mirror,
        &["--format", "json", "--allow-affected"],
        &crates(),
    );
    let after = OffsetDateTime::from(SystemTime::now());
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert_eq!(run.stderr, "");
    assert_eq!(mirror.requests(), ["/crates.io/all.zip"]);
    let report = json_report(&run);
    assert_eq!(report["affected"][0]["id"], json!("RUSTSEC-2020-0071"));
    assert_eq!(report["affected"].as_array().map(Vec::len), Some(1));
    let at = downloaded_at(&run);
    assert!(before <= at && at <= after, "{before} <= {at} <= {after}");
    assert_eq!(
        report["osv"],
        json!([{
            "kind": "archive",
            "ecosystem": "crates.io",
            "url": format!("{}/crates.io/all.zip", mirror.base),
            "downloadedAt": report["osv"][0]["downloadedAt"],
            "lastModified": LAST_MODIFIED,
            "recordCount": 1,
        }])
    );
}

// spec: MCH-4, MCH-22
#[test]
fn the_human_report_gives_the_freshness_of_each_archive() {
    let cache = TempDir::new().expect("a cache");
    let mirror = crates_io_mirror();
    mirror.serve("npm", &["GHSA-35jh-r3h4-6jhm.json"], None);
    let input = bom(
        "1.6",
        &json!([
            component("time", "0.1.43", Some("pkg:cargo/time@0.1.43")),
            component("lodash", "4.17.21", Some("pkg:npm/lodash@4.17.21")),
        ]),
    );
    let json = fetch(cache.path(), &mirror, &["--format", "json"], &input);
    let at = osv_of(&json)[0]["downloadedAt"].clone();
    let at = at.as_str().expect("a string");
    let npm_at = osv_of(&json)[1]["downloadedAt"].clone();
    let npm_at = npm_at.as_str().expect("a string");
    let human = fetch(cache.path(), &mirror, &["--refresh", "offline"], &input);
    assert_eq!(human.code, 1, "{}", human.stderr);
    assert!(
        human.stdout.contains(&format!(
            "OSV records:\n  crates.io: 1 record, downloaded {at} from {base}/crates.io/all.zip, \
             Last-Modified {LAST_MODIFIED}\n  npm: 1 record, downloaded {npm_at} from {base}/npm/all.zip\n",
            base = mirror.base
        )),
        "{}",
        human.stdout
    );
}

// spec: MCH-5
#[test]
fn each_ecosystem_is_fetched_once_in_the_order_of_its_first_component() {
    let cache = TempDir::new().expect("a cache");
    let mirror = crates_io_mirror();
    mirror.serve("npm", &["GHSA-35jh-r3h4-6jhm.json"], None);
    mirror.serve("PyPI", &[], None);
    let input = bom(
        "1.6",
        &json!([
            component("bare", "1.0", None),
            component("lodash", "4.17.20", Some("pkg:npm/lodash@4.17.20")),
            component("time", "0.1.43", Some("pkg:cargo/time@0.1.43")),
            component("left-pad", "1.3.0", Some("pkg:npm/left-pad@1.3.0")),
            component("deb", "1", Some("pkg:deb/debian/curl@1")),
            component("django", "2.1", Some("pkg:pypi/django@2.1")),
        ]),
    );
    let run = fetch(cache.path(), &mirror, &["--format", "json"], &input);
    assert_eq!(run.code, 1, "{}", run.stderr);
    assert_eq!(
        mirror.requests(),
        ["/npm/all.zip", "/crates.io/all.zip", "/PyPI/all.zip"]
    );
    let ecosystems: Vec<Value> = osv_of(&run)
        .as_array()
        .expect("an array")
        .iter()
        .map(|source| source["ecosystem"].clone())
        .collect();
    assert_eq!(
        ecosystems,
        [json!("npm"), json!("crates.io"), json!("PyPI")]
    );
}

// spec: MCH-5, MCH-16
#[test]
fn an_sbom_with_no_ecosystem_fetches_nothing() {
    let cache = TempDir::new().expect("a cache");
    let mirror = Mirror::new();
    let input = bom("1.6", &json!([component("bare", "1.0", None)]));
    let human = fetch(cache.path(), &mirror, &[], &input);
    assert_eq!(human.code, 0, "{}", human.stderr);
    assert!(
        human.stdout.contains("OSV records: none\n"),
        "{}",
        human.stdout
    );
    let json = fetch(cache.path(), &mirror, &["--format", "json"], &input);
    assert_eq!(osv_of(&json), json!([]));
    assert_eq!(
        json_report(&json)["notEvaluated"].as_array().map(Vec::len),
        Some(1)
    );
    assert_eq!(mirror.requests(), Vec::<String>::new());
}

// spec: MCH-5, MCH-11
#[test]
fn a_cache_is_read_back_offline_and_within_the_default_age_without_a_request() {
    let cache = TempDir::new().expect("a cache");
    let mirror = crates_io_mirror();
    let first = fetch(cache.path(), &mirror, &["--format", "json"], &crates());
    assert_eq!(first.code, 1, "{}", first.stderr);
    for args in [
        vec!["--format", "json", "--refresh", "offline"],
        vec!["--format", "json", "--refresh", "if-missing"],
        vec!["--format", "json", "--refresh", "1m"],
        vec!["--format", "json"],
    ] {
        let again = fetch(cache.path(), &mirror, &args, &crates());
        assert_eq!(again.code, 1, "{args:?}: {}", again.stderr);
        assert_eq!(osv_of(&again), osv_of(&first), "{args:?}");
    }
    assert_eq!(mirror.requests(), ["/crates.io/all.zip"]);
}

// spec: MCH-11
#[test]
fn the_policy_always_downloads_again() {
    let cache = TempDir::new().expect("a cache");
    let mirror = crates_io_mirror();
    for _ in 0..2 {
        let run = fetch(cache.path(), &mirror, &["--refresh", "always"], &crates());
        assert_eq!(run.code, 1, "{}", run.stderr);
    }
    assert_eq!(
        mirror.requests(),
        ["/crates.io/all.zip", "/crates.io/all.zip"]
    );
}

// spec: MCH-10, MCH-11
#[test]
fn a_refresh_policy_that_is_not_one_is_refused() {
    let cache = TempDir::new().expect("a cache");
    let mirror = crates_io_mirror();
    for policy in [
        "0d",
        "2w",
        "soon",
        "-1h",
        "h",
        "1.5d",
        "1é",
        "",
        "99999999999999999999d",
    ] {
        let run = fetch(cache.path(), &mirror, &["--refresh", policy], &crates());
        assert_eq!(run.code, 2, "{policy}: {}", run.stderr);
        assert_eq!(run.stdout, "");
    }
    for policy in ["30m", "12h", "7d"] {
        let run = fetch(cache.path(), &mirror, &["--refresh", policy], &crates());
        assert_eq!(run.code, 1, "{policy}: {}", run.stderr);
    }
    assert!(mirror.requests().len() <= 1);
}

// spec: MCH-10, MCH-14
#[test]
fn an_ecosystem_not_cached_offline_is_named_and_exits_with_5() {
    let cache = TempDir::new().expect("a cache");
    let mirror = Mirror::new();
    let run = fetch(cache.path(), &mirror, &["--refresh", "offline"], &crates());
    assert_eq!(run.code, 5);
    assert_eq!(run.stdout, "");
    assert_eq!(run.stderr.lines().count(), 1, "{}", run.stderr);
    assert!(run.stderr.contains("crates.io"), "{}", run.stderr);
    assert!(run.stderr.contains("not cached"), "{}", run.stderr);
    assert_eq!(mirror.requests(), Vec::<String>::new());
}

// spec: MCH-10, MCH-14
#[test]
fn a_failed_download_is_named_and_exits_with_5() {
    let cache = TempDir::new().expect("a cache");
    let mirror = Mirror::new();
    let run = fetch(cache.path(), &mirror, &[], &crates());
    assert_eq!(run.code, 5);
    assert_eq!(run.stdout, "");
    assert!(run.stderr.contains("crates.io"), "{}", run.stderr);
    assert!(run.stderr.contains("cannot download"), "{}", run.stderr);
}

// spec: MCH-10
#[test]
fn an_unreadable_sbom_exits_with_3_before_any_request() {
    let cache = TempDir::new().expect("a cache");
    let mirror = crates_io_mirror();
    let run = fetch(cache.path(), &mirror, &[], b"not json");
    assert_eq!(run.code, 3);
    assert_eq!(mirror.requests(), Vec::<String>::new());
}

// spec: MCH-10
#[test]
fn osv_paths_exclude_the_options_of_the_fetch() {
    let cache = TempDir::new().expect("a cache");
    let osv = Path::new(env!("CARGO_MANIFEST_DIR")).join("../forewarn-osv/tests/fixtures");
    for extra in [
        vec!["--cache", path(cache.path())],
        vec!["--refresh", "always"],
        vec!["--osv-url", "http://127.0.0.1:9"],
    ] {
        let mut args = vec!["match", "--osv", path(&osv)];
        args.extend(extra.iter());
        args.push("-");
        let run = run_with(&args, Some(&crates()), &[]);
        assert_eq!(run.code, 2, "{extra:?}: {}", run.stderr);
    }
}

// spec: MCH-12
#[test]
fn the_default_cache_is_under_xdg_cache_home_else_home() {
    let mirror = crates_io_mirror();
    let xdg = TempDir::new().expect("a directory");
    let home = TempDir::new().expect("a directory");
    let url = ["match", "--osv-url", &mirror.base, "-"];
    let run = run_with(
        &url,
        Some(&crates()),
        &[
            ("XDG_CACHE_HOME", Some(path(xdg.path()))),
            ("HOME", Some(path(home.path()))),
        ],
    );
    assert_eq!(run.code, 1, "{}", run.stderr);
    assert!(xdg.path().join("forewarn/osv/crates.io").is_dir());
    let run = run_with(
        &url,
        Some(&crates()),
        &[
            ("XDG_CACHE_HOME", Some("")),
            ("HOME", Some(path(home.path()))),
        ],
    );
    assert_eq!(run.code, 1, "{}", run.stderr);
    assert!(home.path().join(".cache/forewarn/osv/crates.io").is_dir());
}

// spec: MCH-10, MCH-12
#[test]
fn no_cache_directory_is_an_invalid_argument_unless_osv_paths_are_given() {
    let mirror = crates_io_mirror();
    let unset = [("XDG_CACHE_HOME", None), ("HOME", None)];
    let run = run_with(
        &["match", "--osv-url", &mirror.base, "-"],
        Some(&crates()),
        &unset,
    );
    assert_eq!(run.code, 2, "{}", run.stderr);
    assert_eq!(run.stdout, "");
    assert!(run.stderr.contains("--cache"), "{}", run.stderr);
    assert!(run.stderr.contains("forewarn match"), "{}", run.stderr);
    assert_eq!(mirror.requests(), Vec::<String>::new());
    let osv = Path::new(env!("CARGO_MANIFEST_DIR")).join("../forewarn-osv/tests/fixtures");
    let local = run_with(
        &["match", "--osv", path(&osv), "-"],
        Some(&crates()),
        &unset,
    );
    assert_eq!(local.code, 1, "{}", local.stderr);
}

// spec: MCH-12
#[test]
fn a_relative_xdg_cache_home_is_ignored() {
    let mirror = crates_io_mirror();
    let home = TempDir::new().expect("a directory");
    let work = TempDir::new().expect("a directory");
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_forewarn"));
    let output = command
        .args(["match", "--osv-url", &mirror.base, "-"])
        .current_dir(work.path())
        .env("XDG_CACHE_HOME", ".cache")
        .env("HOME", home.path())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .spawn()
        .and_then(|mut child| {
            child
                .stdin
                .take()
                .expect("stdin is piped")
                .write_all(&crates())?;
            child.wait_with_output()
        })
        .expect("the binary runs");
    assert_eq!(output.status.code(), Some(1));
    assert!(home.path().join(".cache/forewarn/osv/crates.io").is_dir());
    assert!(!work.path().join(".cache").exists());
}
