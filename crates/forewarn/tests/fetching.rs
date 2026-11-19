//! `forewarn match` fetching the OSV archives of the ecosystems of an SBOM, the CISA KEV catalog and the EUVD list into
//! a cache (`specs/cli-match.md`, `specs/cli-match-exploited.md`), against a loopback HTTP server: no test needs the
//! network.

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

    /// Serves at `/kev.json` a KEV catalog of version `2026.11.12`, released 2026-11-12, naming `CVE-2020-26235`
    /// (`time` 0.1.43) added on 2021-12-10.
    fn serve_kev(&self) {
        let catalog = json!({
            "catalogVersion": "2026.11.12",
            "dateReleased": "2026-11-12T18:00:00.000Z",
            "vulnerabilities": [{"cveID": "CVE-2020-26235", "dateAdded": "2021-12-10"}],
        });
        self.routes.lock().expect("the routes").insert(
            "/kev.json".to_owned(),
            (
                serde_json::to_vec(&catalog).expect("serializes"),
                Some(LAST_MODIFIED),
            ),
        );
    }

    /// Serves at `/api/search` one page of EUVD naming `CVE-2020-26235` (`time` 0.1.43), exploited since 2021-12-11.
    fn serve_euvd(&self) {
        let page = json!({
            "items": [{
                "id": "EUVD-2020-23577",
                "aliases": "GHSA-wcg3-cvx6-7396\nCVE-2020-26235\n",
                "exploitedSince": "Dec 11, 2021, 12:00:00 AM",
            }],
            "total": 1,
        });
        self.routes.lock().expect("the routes").insert(
            EUVD_PAGE_0.to_owned(),
            (serde_json::to_vec(&page).expect("serializes"), None),
        );
    }

    fn euvd_url(&self) -> String {
        format!("{}/api/search", self.base)
    }

    fn kev_url(&self) -> String {
        format!("{}/kev.json", self.base)
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().expect("the requests").clone()
    }
}

/// The path of page 0 of the EUVD search.
const EUVD_PAGE_0: &str = "/api/search?exploited=true&size=100&page=0";

const LAST_MODIFIED: &str = "Wed, 11 Nov 2026 08:00:00 GMT";

/// The KEV catalog of the KEV adapter's tests, naming `CVE-2021-44228` and `CVE-2023-4966`.
const KEV_FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../forewarn-exploited/tests/fixtures/kev.json"
);

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
    let mut all = vec![
        "match",
        "--no-euvd",
        "--no-kev",
        "--cache",
        path(cache),
        "--osv-url",
        &mirror.base,
    ];
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
    assert_eq!(report["affected"][0]["id"], json!("CVE-2020-26235"));
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
            component("apk", "1", Some("pkg:apk/alpine/curl@1")),
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
        let mut args = vec!["match", "--no-euvd", "--osv", path(&osv), "--no-kev"];
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
    let url = [
        "match",
        "--no-euvd",
        "--no-kev",
        "--osv-url",
        &mirror.base,
        "-",
    ];
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
fn no_cache_directory_is_an_invalid_argument_unless_nothing_is_fetched() {
    let mirror = crates_io_mirror();
    let unset = [("XDG_CACHE_HOME", None), ("HOME", None)];
    let run = run_with(
        &[
            "match",
            "--no-euvd",
            "--no-kev",
            "--osv-url",
            &mirror.base,
            "-",
        ],
        Some(&crates()),
        &unset,
    );
    assert_eq!(run.code, 2, "{}", run.stderr);
    assert_eq!(run.stdout, "");
    assert!(run.stderr.contains("--cache"), "{}", run.stderr);
    assert!(run.stderr.contains("forewarn match"), "{}", run.stderr);
    assert_eq!(mirror.requests(), Vec::<String>::new());
    let osv = Path::new(env!("CARGO_MANIFEST_DIR")).join("../forewarn-osv/tests/fixtures");
    let fetched_kev = run_with(
        &["match", "--no-euvd", "--osv", path(&osv), "-"],
        Some(&crates()),
        &unset,
    );
    assert_eq!(fetched_kev.code, 2, "{}", fetched_kev.stderr);
    assert!(
        fetched_kev.stderr.contains("--no-kev"),
        "{}",
        fetched_kev.stderr
    );
    for kev in [vec!["--no-kev"], vec!["--kev", KEV_FIXTURE]] {
        let mut args = vec!["match", "--no-euvd", "--osv", path(&osv)];
        args.extend(kev.iter());
        args.push("-");
        let local = run_with(&args, Some(&crates()), &unset);
        assert_eq!(local.code, 1, "{kev:?}: {}", local.stderr);
    }
}

// spec: MCH-12
#[test]
fn a_relative_xdg_cache_home_is_ignored() {
    let mirror = crates_io_mirror();
    let home = TempDir::new().expect("a directory");
    let work = TempDir::new().expect("a directory");
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_forewarn"));
    let output = command
        .args([
            "match",
            "--no-euvd",
            "--no-kev",
            "--osv-url",
            &mirror.base,
            "-",
        ])
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

/// Runs `forewarn match` with `args` on `sbom`, the cache in `cache`, the archives and the KEV catalog from `mirror`.
fn fetch_with_kev(cache: &Path, mirror: &Mirror, args: &[&str], sbom: &[u8]) -> Run {
    let kev_url = mirror.kev_url();
    let mut all = vec![
        "match",
        "--no-euvd",
        "--cache",
        path(cache),
        "--kev-url",
        &kev_url,
    ];
    all.extend_from_slice(args);
    all.push("-");
    run_with(&all, Some(sbom), &[])
}

// spec: MXL-H1, MXL-1, MXL-2, MXL-5, MXL-10, MXL-11, MCH-10
#[test]
fn a_ci_job_fetches_the_kev_catalog_into_its_cache_and_sees_the_exploited_match() {
    let cache = TempDir::new().expect("a cache");
    let mirror = crates_io_mirror();
    mirror.serve_kev();
    let osv_url = ["--osv-url", &mirror.base];
    let human = fetch_with_kev(cache.path(), &mirror, &osv_url, &crates());
    assert_eq!(human.code, 6, "{}", human.stderr);
    assert_eq!(human.stderr, "");
    assert_eq!(mirror.requests(), ["/crates.io/all.zip", "/kev.json"]);
    assert!(cache.path().join("cisa-kev").is_dir());
    let json = fetch_with_kev(
        cache.path(),
        &mirror,
        &["--osv-url", &mirror.base, "--format", "json"],
        &crates(),
    );
    let report = json_report(&json);
    let list = &report["exploitedLists"][0];
    let at = list["downloadedAt"].as_str().expect("a time").to_owned();
    OffsetDateTime::parse(&at, &Rfc3339).expect("RFC 3339");
    assert_eq!(
        report["exploitedLists"],
        json!([{
            "kind": "fetched",
            "name": "CISA KEV",
            "version": "2026.11.12",
            "released": "2026-11-12",
            "url": mirror.kev_url(),
            "downloadedAt": at,
            "lastModified": LAST_MODIFIED,
            "entryCount": 1,
        }])
    );
    assert_eq!(report["exploitedCount"], 1);
    assert_eq!(
        report["affected"][0]["exploited"],
        json!([{"list": "CISA KEV", "cve": "CVE-2020-26235", "dateAdded": "2021-12-10"}])
    );
    assert!(
        human.stdout.contains(&format!(
            "Exploited lists:\n  CISA KEV: catalog 2026.11.12 released 2026-11-12, 1 entry, downloaded {at} \
             from {}, Last-Modified {LAST_MODIFIED}\nReporting deadlines",
            mirror.kev_url()
        )),
        "{}",
        human.stdout
    );
    assert!(
        human
            .stdout
            .contains("\nAffected (1, 1 actively exploited):\n"),
        "{}",
        human.stdout
    );
    assert!(
        human
            .stdout
            .contains("\n    actively exploited: CISA KEV CVE-2020-26235 added 2021-12-10\n"),
        "{}",
        human.stdout
    );
}

// spec: MXL-2, MXL-11
#[test]
fn the_cached_catalog_is_read_back_offline_without_a_request() {
    let cache = TempDir::new().expect("a cache");
    let mirror = crates_io_mirror();
    mirror.serve_kev();
    let args = ["--osv-url", &mirror.base, "--format", "json"];
    let first = fetch_with_kev(cache.path(), &mirror, &args, &crates());
    assert_eq!(first.code, 6, "{}", first.stderr);
    let offline = [&args[..], &["--refresh", "offline"]].concat();
    let second = fetch_with_kev(cache.path(), &mirror, &offline, &crates());
    assert_eq!(second.code, 6, "{}", second.stderr);
    assert_eq!(mirror.requests().len(), 2, "{:?}", mirror.requests());
    assert_eq!(
        json_report(&second)["exploitedLists"],
        json_report(&first)["exploitedLists"]
    );
}

// spec: MCH-6, MCH-10, MXL-2
#[test]
fn local_osv_records_still_fetch_the_catalog_under_the_refresh_policy() {
    let cache = TempDir::new().expect("a cache");
    let mirror = Mirror::new();
    mirror.serve_kev();
    let osv = Path::new(env!("CARGO_MANIFEST_DIR")).join("../forewarn-osv/tests/fixtures");
    let args = ["--osv", path(&osv), "--refresh", "always"];
    for _ in 0..2 {
        let run = fetch_with_kev(cache.path(), &mirror, &args, &crates());
        assert_eq!(run.code, 6, "{}", run.stderr);
    }
    assert_eq!(mirror.requests(), ["/kev.json", "/kev.json"]);
}

// spec: MCH-10, MCH-14, MXL-2
#[test]
fn a_catalog_not_cached_offline_is_named_and_exits_with_5() {
    let cache = TempDir::new().expect("a cache");
    let mirror = Mirror::new();
    let osv = Path::new(env!("CARGO_MANIFEST_DIR")).join("../forewarn-osv/tests/fixtures");
    let run = fetch_with_kev(
        cache.path(),
        &mirror,
        &["--osv", path(&osv), "--refresh", "offline"],
        &crates(),
    );
    assert_eq!(run.code, 5, "{}", run.stderr);
    assert_eq!(run.stdout, "");
    assert_eq!(run.stderr.lines().count(), 1, "{}", run.stderr);
    assert!(
        run.stderr.contains("CISA KEV") && run.stderr.contains("not cached"),
        "{}",
        run.stderr
    );
    assert_eq!(mirror.requests(), Vec::<String>::new());
}

// spec: MXL-3, MXL-4
#[test]
fn a_kev_file_or_no_kev_sends_no_request_for_the_catalog() {
    let mirror = crates_io_mirror();
    mirror.serve_kev();
    for kev in [vec!["--kev", KEV_FIXTURE], vec!["--no-kev"]] {
        let cache = TempDir::new().expect("a cache");
        let mut args = vec![
            "match",
            "--no-euvd",
            "--cache",
            path(cache.path()),
            "--osv-url",
            &mirror.base,
        ];
        args.extend(kev.iter());
        args.push("-");
        let run = run_with(&args, Some(&crates()), &[]);
        assert_eq!(run.code, 1, "{kev:?}: {}", run.stderr);
        assert!(!cache.path().join("cisa-kev").exists());
    }
    assert_eq!(
        mirror.requests(),
        ["/crates.io/all.zip", "/crates.io/all.zip"]
    );
}

// spec: MCH-10, MXL-3, MXL-4
#[test]
fn the_kev_options_exclude_each_other() {
    for kev in [
        vec!["--kev", KEV_FIXTURE, "--no-kev"],
        vec!["--kev", KEV_FIXTURE, "--kev-url", "http://127.0.0.1:9"],
        vec!["--no-kev", "--kev-url", "http://127.0.0.1:9"],
    ] {
        let mut args = vec!["match", "--no-euvd", "--osv", KEV_FIXTURE];
        args.extend(kev.iter());
        args.push("-");
        let run = run_with(&args, Some(&crates()), &[]);
        assert_eq!(run.code, 2, "{kev:?}: {}", run.stderr);
    }
}

/// Runs `forewarn match` with `args` on `sbom`, the cache in `cache`, the EUVD list and, unless `args` names `--kev`
/// or `--no-kev`, the KEV catalog from `mirror`.
fn fetch_with_euvd(cache: &Path, mirror: &Mirror, args: &[&str], sbom: &[u8]) -> Run {
    let (kev_url, euvd_url) = (mirror.kev_url(), mirror.euvd_url());
    let mut all = vec!["match", "--cache", path(cache), "--euvd-url", &euvd_url];
    if !args.iter().any(|arg| ["--kev", "--no-kev"].contains(arg)) {
        all.extend(["--kev-url", &kev_url]);
    }
    all.extend_from_slice(args);
    all.push("-");
    run_with(&all, Some(sbom), &[])
}

fn osv_fixtures() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../forewarn-osv/tests/fixtures")
}

// spec: MXL-H3, MXL-6, MXL-5, MXL-1, MXL-12, MXL-13, MCH-16
#[test]
fn a_ci_job_pages_the_euvd_list_into_its_cache_and_sees_its_evidence_after_kev() {
    let cache = TempDir::new().expect("a cache");
    let mirror = Mirror::new();
    mirror.serve_kev();
    mirror.serve_euvd();
    let osv = osv_fixtures();
    let json = fetch_with_euvd(
        cache.path(),
        &mirror,
        &["--osv", path(&osv), "--format", "json"],
        &crates(),
    );
    assert_eq!(json.code, 6, "{}", json.stderr);
    assert_eq!(mirror.requests(), ["/kev.json", EUVD_PAGE_0]);
    assert!(cache.path().join("euvd-exploited").is_dir());
    let report = json_report(&json);
    let euvd = &report["exploitedLists"][1];
    let at = euvd["downloadedAt"].as_str().expect("a time").to_owned();
    OffsetDateTime::parse(&at, &Rfc3339).expect("RFC 3339");
    assert_eq!(report["exploitedLists"][0]["name"], "CISA KEV");
    assert_eq!(
        *euvd,
        json!({
            "kind": "fetched",
            "name": "EUVD",
            "version": null,
            "released": null,
            "url": mirror.euvd_url(),
            "downloadedAt": at,
            "lastModified": null,
            "entryCount": 1,
        })
    );
    assert_eq!(
        report["affected"][0]["exploited"],
        json!([
            {"list": "CISA KEV", "cve": "CVE-2020-26235", "dateAdded": "2021-12-10"},
            {"list": "EUVD", "cve": "CVE-2020-26235", "dateAdded": "2021-12-11"},
        ])
    );
    let human = fetch_with_euvd(cache.path(), &mirror, &["--osv", path(&osv)], &crates());
    assert_eq!(human.code, 6, "{}", human.stderr);
    assert!(
        human.stdout.contains(&format!(
            "\n  EUVD: 1 entry, downloaded {at} from {}\n",
            mirror.euvd_url()
        )),
        "{}",
        human.stdout
    );
    assert!(
        human.stdout.contains(
            "actively exploited: CISA KEV CVE-2020-26235 added 2021-12-10; EUVD CVE-2020-26235 added 2021-12-11\n"
        ),
        "{}",
        human.stdout
    );
}

// spec: MXL-6, MXL-13
#[test]
fn the_cached_euvd_list_is_read_back_offline_without_a_request() {
    let cache = TempDir::new().expect("a cache");
    let mirror = Mirror::new();
    mirror.serve_euvd();
    let osv = osv_fixtures();
    let args = ["--osv", path(&osv), "--no-kev", "--format", "json"];
    let first = fetch_with_euvd(cache.path(), &mirror, &args, &crates());
    assert_eq!(first.code, 6, "{}", first.stderr);
    let offline = [&args[..], &["--refresh", "offline"]].concat();
    let second = fetch_with_euvd(cache.path(), &mirror, &offline, &crates());
    assert_eq!(second.code, 6, "{}", second.stderr);
    assert_eq!(mirror.requests(), [EUVD_PAGE_0]);
    assert_eq!(
        json_report(&second)["exploitedLists"],
        json_report(&first)["exploitedLists"]
    );
}

// spec: MXL-8, MXL-7
#[test]
fn an_euvd_file_or_no_euvd_sends_no_request_to_euvd() {
    let mirror = Mirror::new();
    mirror.serve_euvd();
    let osv = osv_fixtures();
    let directory = TempDir::new().expect("a directory");
    let file = directory.path().join("euvd.json");
    fs::write(&file, r#"{"items": []}"#).expect("written");
    let euvd_url = mirror.euvd_url();
    for euvd in [vec!["--euvd", path(&file)], vec!["--no-euvd"]] {
        let mut args = vec!["match", "--osv", path(&osv), "--kev", KEV_FIXTURE];
        args.extend(euvd.iter());
        args.push("-");
        let run = run_with(&args, Some(&crates()), &[]);
        assert_eq!(run.code, 1, "{euvd:?}: {}", run.stderr);
    }
    let mut paged = vec!["match", "--osv", path(&osv), "--kev", KEV_FIXTURE];
    let cache = TempDir::new().expect("a cache");
    paged.extend(["--cache", path(cache.path()), "--euvd-url", &euvd_url, "-"]);
    assert_eq!(run_with(&paged, Some(&crates()), &[]).code, 6);
    assert_eq!(
        mirror.requests(),
        [EUVD_PAGE_0],
        "paged only without --euvd nor --no-euvd"
    );
}

// spec: MCH-10, MCH-14, MXL-6
#[test]
fn an_euvd_list_that_cannot_be_paged_is_named_and_exits_with_5() {
    let cache = TempDir::new().expect("a cache");
    let mirror = Mirror::new();
    let osv = osv_fixtures();
    let run = fetch_with_euvd(
        cache.path(),
        &mirror,
        &["--osv", path(&osv), "--no-kev"],
        &crates(),
    );
    assert_eq!(run.code, 5, "{}", run.stderr);
    assert_eq!(run.stdout, "");
    assert_eq!(run.stderr.lines().count(), 1, "{}", run.stderr);
    assert!(
        run.stderr.contains("EUVD") && run.stderr.contains("cannot download"),
        "{}",
        run.stderr
    );
}

// spec: MCH-10, MXL-7, MXL-8
#[test]
fn the_euvd_options_exclude_each_other_and_cache_applies_to_the_euvd_list() {
    for euvd in [
        vec!["--euvd", KEV_FIXTURE, "--no-euvd"],
        vec!["--euvd", KEV_FIXTURE, "--euvd-url", "http://127.0.0.1:9"],
        vec!["--no-euvd", "--euvd-url", "http://127.0.0.1:9"],
        vec!["--no-euvd", "--cache", "cache"],
    ] {
        let mut args = vec!["match", "--osv", KEV_FIXTURE, "--kev", KEV_FIXTURE];
        args.extend(euvd.iter());
        args.push("-");
        let run = run_with(&args, Some(&crates()), &[]);
        assert_eq!(run.code, 2, "{euvd:?}: {}", run.stderr);
    }
    let cache = TempDir::new().expect("a cache");
    let mirror = Mirror::new();
    mirror.serve_euvd();
    let osv = osv_fixtures();
    let run = fetch_with_euvd(
        cache.path(),
        &mirror,
        &["--osv", path(&osv), "--kev", KEV_FIXTURE],
        &crates(),
    );
    assert_eq!(run.code, 6, "{}", run.stderr);
}

// spec: MCH-10, MCH-12
#[test]
fn no_cache_directory_names_every_list_to_give_or_skip() {
    let unset = [("XDG_CACHE_HOME", None), ("HOME", None)];
    let osv = osv_fixtures();
    let run = run_with(
        &["match", "--osv", path(&osv), "-"],
        Some(&crates()),
        &unset,
    );
    assert_eq!(run.code, 2, "{}", run.stderr);
    assert!(
        run.stderr
            .contains("give --kev <file> or --no-kev, and --euvd <file> or --no-euvd, to fetch no exploited list"),
        "{}",
        run.stderr
    );
    let euvd_only = run_with(
        &["match", "--osv", path(&osv), "--no-kev", "-"],
        Some(&crates()),
        &unset,
    );
    assert_eq!(euvd_only.code, 2, "{}", euvd_only.stderr);
    assert!(
        euvd_only
            .stderr
            .contains("give --euvd <file> or --no-euvd to fetch no EUVD list"),
        "{}",
        euvd_only.stderr
    );
}
