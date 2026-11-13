//! `forewarn match --osv-api` querying the OSV API for the components of an SBOM (`specs/cli-match.md`), against a
//! loopback HTTP server: no test needs the network.

mod common;

use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;

use common::{Run, bom, json_report, run_with};
use serde_json::{Value, json};
use tempfile::TempDir;

/// A request the loopback server received: `<method> <path>`, and its body when it had one.
type Request = (String, Option<Value>);

/// A loopback HTTP server playing the OSV API: `querybatch` names `RUSTSEC-2020-0071` for `time` and nothing for
/// any other package, `/v1/vulns/RUSTSEC-2020-0071` serves its record, every other path answers 404; or every request
/// answers `status` when one is given.
struct OsvApi {
    base: String,
    requests: Arc<Mutex<Vec<Request>>>,
}

impl OsvApi {
    fn new(status: Option<u16>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        let base = format!("http://{}", listener.local_addr().expect("an address"));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&requests);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let (line, body) = read_request(&mut stream);
                seen.lock()
                    .expect("the requests")
                    .push((line.clone(), body.clone()));
                let (status, reply) = match (status, line.as_str(), body) {
                    (Some(status), _, _) => (status, b"busy".to_vec()),
                    (None, "POST /v1/querybatch", Some(body)) => (200, results(&body)),
                    (None, "GET /v1/vulns/RUSTSEC-2020-0071", None) => (200, record()),
                    _ => (404, b"not found".to_vec()),
                };
                let head = format!(
                    "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    reply.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(&reply);
            }
        });
        Self { base, requests }
    }

    fn requests(&self) -> Vec<Request> {
        self.requests.lock().expect("the requests").clone()
    }

    fn lines(&self) -> Vec<String> {
        self.requests().into_iter().map(|(line, _)| line).collect()
    }
}

fn read_request(stream: &mut impl Read) -> (String, Option<Value>) {
    let mut head = Vec::new();
    let mut byte = [0; 1];
    while !head.ends_with(b"\r\n\r\n") && stream.read(&mut byte).is_ok_and(|n| n == 1) {
        head.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    let line: Vec<&str> = head
        .lines()
        .next()
        .unwrap_or_default()
        .split(' ')
        .take(2)
        .collect();
    let length = head.lines().find_map(|header| {
        let (name, value) = header.split_once(':')?;
        name.eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse::<usize>().ok())
            .flatten()
    });
    let body = length.map(|length| {
        let mut body = vec![0; length];
        let _ = stream.read_exact(&mut body);
        serde_json::from_slice(&body).expect("a JSON body")
    });
    (line.join(" "), body)
}

fn results(body: &Value) -> Vec<u8> {
    let results: Vec<Value> = body["queries"]
        .as_array()
        .expect("queries")
        .iter()
        .map(|query| {
            if query["package"]["name"] == "time" {
                json!({"vulns": [{"id": "RUSTSEC-2020-0071", "modified": "2026-01-01T00:00:00Z"}]})
            } else {
                json!({})
            }
        })
        .collect();
    json!({ "results": results }).to_string().into_bytes()
}

fn record() -> Vec<u8> {
    fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../forewarn-osv/tests/fixtures/RUSTSEC-2020-0071.json"),
    )
    .expect("the fixture is read")
}

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
            component("time", "0.1.43", Some("pkg:cargo/time@0.1.43?arch=x86_64")),
            component("serde", "1.0.0", Some("pkg:cargo/serde@1.0.0")),
        ]),
    )
}

/// Runs `forewarn match --osv-api` with `args` on `sbom` from standard input, the API at `api`.
fn query(api: &OsvApi, args: &[&str], sbom: &[u8]) -> Run {
    let mut all = vec![
        "match",
        "--no-euvd",
        "--no-kev",
        "--osv-api",
        "--osv-api-url",
        &api.base,
    ];
    all.extend_from_slice(args);
    all.push("-");
    run_with(&all, Some(sbom), &[])
}

// spec: MCH-H3, MCH-24, MCH-26, MCH-27
#[test]
fn a_vendor_queries_the_osv_api_for_the_components_of_an_sbom() {
    let api = OsvApi::new(None);

    let run = query(&api, &[], &crates());

    assert_eq!(run.code, 1, "{}", run.stderr);
    assert_eq!(run.stderr, "");
    assert_eq!(
        api.lines(),
        ["POST /v1/querybatch", "GET /v1/vulns/RUSTSEC-2020-0071"]
    );
    assert_eq!(
        api.requests()[0].1,
        Some(json!({"queries": [
            {"package": {"ecosystem": "crates.io", "name": "time"}, "version": "0.1.43"},
            {"package": {"ecosystem": "crates.io", "name": "serde"}, "version": "1.0.0"},
        ]}))
    );
    let source = run
        .stdout
        .lines()
        .find(|line| line.contains("OSV API"))
        .unwrap_or_else(|| panic!("no API source: {}", run.stdout));
    assert!(source.contains("1 record, queried "), "{source}");
    assert!(
        source.ends_with(&format!("Z from {}", api.base)),
        "{source}"
    );
    assert!(
        run.stdout.contains("time 0.1.43") && run.stdout.contains("RUSTSEC-2020-0071"),
        "{}",
        run.stdout
    );
}

// spec: MCH-16, MCH-26
#[test]
fn the_json_report_gives_the_api_as_the_source() {
    let api = OsvApi::new(None);

    let run = query(&api, &["--format", "json"], &crates());

    assert_eq!(run.code, 1, "{}", run.stderr);
    let report = json_report(&run);
    let queried_at = report["osv"][0]["queriedAt"].as_str().expect("a string");
    assert_eq!(
        queried_at.len(),
        "2026-11-13T10:00:00Z".len(),
        "{queried_at}"
    );
    assert!(queried_at.ends_with('Z'), "{queried_at}");
    assert_eq!(
        report["osv"],
        json!([{
            "kind": "api",
            "url": api.base,
            "queriedAt": queried_at,
            "recordCount": 1,
        }])
    );
    assert_eq!(report["affected"][0]["id"], json!("CVE-2020-26235"));
}

// spec: MCH-24
#[test]
fn an_sbom_with_no_ecosystem_sends_no_query() {
    let api = OsvApi::new(None);
    let sbom = bom("1.6", &json!([component("app", "1.0.0", None)]));

    let run = query(&api, &["--format", "json"], &sbom);

    assert_eq!(run.code, 0, "{}", run.stderr);
    assert_eq!(api.lines(), Vec::<String>::new());
    assert_eq!(json_report(&run)["osv"][0]["recordCount"], json!(0));
}

// spec: MCH-25
#[test]
fn without_the_flag_the_api_is_not_queried() {
    let server = OsvApi::new(None);
    let cache = TempDir::new().expect("a cache");

    let run = run_with(
        &[
            "match",
            "--no-euvd",
            "--no-kev",
            "--cache",
            cache.path().to_str().expect("UTF-8"),
            "--osv-url",
            &server.base,
            "-",
        ],
        Some(&crates()),
        &[],
    );

    assert_eq!(run.code, 5, "{}", run.stderr);
    assert_eq!(server.lines(), ["GET /crates.io/all.zip"]);
}

// spec: MCH-10
#[test]
fn the_api_excludes_the_options_of_the_archives_and_the_local_records() {
    let osv = Path::new(env!("CARGO_MANIFEST_DIR")).join("../forewarn-osv/tests/fixtures");
    for extra in [
        vec!["--osv", osv.to_str().expect("UTF-8")],
        vec!["--cache", "cache"],
        vec!["--refresh", "always"],
        vec!["--osv-url", "http://127.0.0.1:9"],
    ] {
        let mut args = vec!["match", "--no-euvd", "--osv-api", "--no-kev"];
        args.extend(extra.iter());
        args.push("-");
        let run = run_with(&args, Some(&crates()), &[]);
        assert_eq!(run.code, 2, "{extra:?}: {}", run.stderr);
    }
    let run = run_with(
        &[
            "match",
            "--no-euvd",
            "--osv-api-url",
            "http://127.0.0.1:9",
            "-",
        ],
        Some(&crates()),
        &[],
    );
    assert_eq!(run.code, 2, "{}", run.stderr);
}

// spec: MCH-10, MCH-12, MCH-24
#[test]
fn the_api_needs_no_cache_directory() {
    let api = OsvApi::new(None);

    let run = run_with(
        &[
            "match",
            "--no-euvd",
            "--osv-api",
            "--no-kev",
            "--osv-api-url",
            &api.base,
            "-",
        ],
        Some(&crates()),
        &[("XDG_CACHE_HOME", None), ("HOME", None)],
    );

    assert_eq!(run.code, 1, "{}", run.stderr);
}

// spec: MCH-10, MCH-14
#[test]
fn a_failed_query_is_named_and_exits_with_5() {
    let api = OsvApi::new(Some(503));

    let run = query(&api, &[], &crates());

    assert_eq!(run.code, 5, "{}", run.stderr);
    assert_eq!(run.stdout, "");
    assert_eq!(run.stderr.lines().count(), 1, "{}", run.stderr);
    assert!(
        run.stderr.contains("cannot query the OSV API") && run.stderr.contains("503"),
        "{}",
        run.stderr
    );
}

// spec: MCH-28
#[test]
fn the_help_says_what_the_api_receives() {
    let run = run_with(&["match", "--no-euvd", "--help"], None, &[]);

    assert_eq!(run.code, 0, "{}", run.stderr);
    let help = run.stdout.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(help.contains("--osv-api"), "{help}");
    assert!(
        help.contains("sends the OSV ecosystem, name and version of each component to the OSV API"),
        "{help}"
    );
}

// spec: MCH-24
#[test]
fn a_go_version_is_queried_without_its_leading_v() {
    let api = OsvApi::new(None);
    let sbom = bom(
        "1.6",
        &json!([component(
            "y",
            "v1.2.3",
            Some("pkg:golang/github.com/x/y@v1.2.3")
        )]),
    );

    let run = query(&api, &[], &sbom);

    assert_eq!(run.code, 0, "{}", run.stderr);
    assert_eq!(
        api.requests()[0].1,
        Some(json!({"queries": [
            {"package": {"ecosystem": "Go", "name": "github.com/x/y"}, "version": "1.2.3"},
        ]}))
    );
}
