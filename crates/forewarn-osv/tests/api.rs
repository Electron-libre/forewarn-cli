//! Querying the OSV API for the records of some packages (`specs/osv-reading.md`), against a loopback HTTP server: no
//! test needs the network.

use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime};

use forewarn_osv::Cause;
use forewarn_osv::api::{Api, OSV_API, Package, QueryError};
use serde_json::{Value, json};

/// A request the loopback server received: method, path, and body when it had one.
#[derive(Clone, Debug)]
struct Request {
    method: String,
    path: String,
    body: Option<Vec<u8>>,
}

impl Request {
    fn json(&self) -> Value {
        serde_json::from_slice(self.body.as_deref().expect("a body")).expect("a JSON body")
    }
}

type Handler = dyn Fn(&Request) -> (u16, Vec<u8>) + Send + Sync;

/// A loopback HTTP server answering each request with a handler, and recording each request.
struct Server {
    base: String,
    requests: Arc<Mutex<Vec<Request>>>,
}

impl Server {
    fn new(handler: impl Fn(&Request) -> (u16, Vec<u8>) + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        let base = format!("http://{}", listener.local_addr().expect("an address"));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&requests);
        let handler: Arc<Handler> = Arc::new(handler);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let request = read_request(&mut stream);
                seen.lock().expect("the requests").push(request.clone());
                let (status, body) = handler(&request);
                let head = format!(
                    "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(&body);
            }
        });
        Self { base, requests }
    }

    fn requests(&self) -> Vec<Request> {
        self.requests.lock().expect("the requests").clone()
    }

    fn lines(&self) -> Vec<String> {
        self.requests()
            .iter()
            .map(|r| {
                format!(
                    "{} {}{}",
                    r.method,
                    r.path,
                    if r.body.is_some() { " with a body" } else { "" }
                )
            })
            .collect()
    }

    fn api(&self) -> Api {
        Api {
            base_url: self.base.clone(),
        }
    }
}

fn read_request(stream: &mut impl Read) -> Request {
    let mut head = Vec::new();
    let mut byte = [0; 1];
    while !head.ends_with(b"\r\n\r\n") && stream.read(&mut byte).is_ok_and(|n| n == 1) {
        head.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    let line = head.lines().next().unwrap_or_default();
    let mut parts = line.split(' ');
    let method = parts.next().unwrap_or_default().to_owned();
    let path = parts.next().unwrap_or_default().to_owned();
    let length = head.lines().find_map(|header| {
        let (name, value) = header.split_once(':')?;
        name.eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse::<usize>().ok())
            .flatten()
    });
    let body = length.map(|length| {
        let mut body = vec![0; length];
        let _ = stream.read_exact(&mut body);
        body
    });
    Request { method, path, body }
}

fn fixture(name: &str) -> Vec<u8> {
    fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name),
    )
    .expect("the fixture is read")
}

fn ok(body: &Value) -> (u16, Vec<u8>) {
    (200, body.to_string().into_bytes())
}

/// The answer of `querybatch` naming, for each query of the request, the ids `ids` gives for its package name.
fn answer(request: &Request, ids: impl Fn(&str) -> Vec<&'static str>) -> (u16, Vec<u8>) {
    let results: Vec<Value> = request.json()["queries"]
        .as_array()
        .expect("queries")
        .iter()
        .map(|query| {
            let ids = ids(query["package"]["name"].as_str().expect("a name"));
            if ids.is_empty() {
                json!({})
            } else {
                json!({"vulns": ids.iter().map(|id| json!({"id": id, "modified": "2026-01-01T00:00:00Z"})).collect::<Vec<_>>()})
            }
        })
        .collect();
    ok(&json!({ "results": results }))
}

/// A record with only an id and one crates.io package.
fn record(id: &str) -> Vec<u8> {
    json!({"id": id, "affected": [{"package": {"ecosystem": "crates.io", "name": "x"}}]})
        .to_string()
        .into_bytes()
}

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
}

fn package(name: &str, version: &str) -> Package {
    Package {
        ecosystem: "crates.io".to_owned(),
        name: name.to_owned(),
        version: version.to_owned(),
    }
}

fn query_error(server: &Server, packages: &[Package]) -> QueryError {
    server
        .api()
        .query(packages, || at(1_000))
        .expect_err("the query fails")
}

// spec: OSR-H6, OSR-24, OSR-25, OSR-26, OSR-27, OSR-29
#[test]
fn the_records_the_api_names_are_read_with_the_time_of_the_query() {
    let server = Server::new(|request| match request.path.as_str() {
        "/v1/querybatch" => answer(request, |name| {
            if name == "time" {
                vec!["RUSTSEC-2020-0071"]
            } else {
                vec![]
            }
        }),
        "/v1/vulns/RUSTSEC-2020-0071" => (200, fixture("RUSTSEC-2020-0071.json")),
        _ => (404, b"not found".to_vec()),
    });

    let answer = server
        .api()
        .query(
            &[package("time", "0.1.43"), package("serde", "1.0.0")],
            || at(1_000),
        )
        .expect("the query succeeds");

    assert_eq!(
        server.lines(),
        [
            "POST /v1/querybatch with a body",
            "GET /v1/vulns/RUSTSEC-2020-0071"
        ]
    );
    assert_eq!(
        server.requests()[0].json(),
        json!({"queries": [
            {"package": {"ecosystem": "crates.io", "name": "time"}, "version": "0.1.43"},
            {"package": {"ecosystem": "crates.io", "name": "serde"}, "version": "1.0.0"},
        ]})
    );
    let ids: Vec<&str> = answer
        .vulnerabilities
        .iter()
        .map(|v| v.id.as_str())
        .collect();
    assert_eq!(ids, ["RUSTSEC-2020-0071"]);
    assert_eq!(answer.vulnerabilities[0].aliases[0], "CVE-2020-26235");
    assert_eq!(answer.freshness.queried_at, at(1_000));
    assert_eq!(answer.freshness.url, server.base);
}

// spec: OSR-26
#[test]
fn the_default_api_is_osv_dev() {
    assert_eq!(Api::default().base_url, "https://api.osv.dev");
    assert_eq!(OSV_API, "https://api.osv.dev");
}

// spec: OSR-26
#[test]
fn the_queries_are_sent_in_batches_of_1000() {
    let server = Server::new(|request| answer(request, |_| vec![]));
    let packages: Vec<Package> = (0..1001)
        .map(|i| package(&format!("p{i}"), "1.0.0"))
        .collect();

    server
        .api()
        .query(&packages, || at(1_000))
        .expect("the query succeeds");

    let sizes: Vec<usize> = server
        .requests()
        .iter()
        .map(|r| r.json()["queries"].as_array().expect("queries").len())
        .collect();
    assert_eq!(sizes, [1000, 1]);
    assert_eq!(
        server.requests()[1].json()["queries"][0]["package"]["name"],
        "p1000"
    );
}

// spec: OSR-26
#[test]
fn a_package_listed_twice_is_queried_once() {
    let server = Server::new(|request| answer(request, |_| vec![]));

    server
        .api()
        .query(
            &[
                package("time", "0.1.43"),
                package("serde", "1.0.0"),
                package("time", "0.1.43"),
            ],
            || at(1_000),
        )
        .expect("the query succeeds");

    let names: Vec<Value> = server.requests()[0].json()["queries"]
        .as_array()
        .expect("queries")
        .iter()
        .map(|query| query["package"]["name"].clone())
        .collect();
    assert_eq!(names, [json!("time"), json!("serde")]);
}

// spec: OSR-24, OSR-29
#[test]
fn an_id_named_for_two_packages_is_read_once() {
    let server = Server::new(|request| {
        if request.path == "/v1/querybatch" {
            answer(request, |_| vec!["RUSTSEC-1"])
        } else {
            (200, record("RUSTSEC-1"))
        }
    });

    let answer = server
        .api()
        .query(&[package("a", "1.0.0"), package("b", "1.0.0")], || {
            at(1_000)
        })
        .expect("the query succeeds");

    assert_eq!(
        server.lines(),
        ["POST /v1/querybatch with a body", "GET /v1/vulns/RUSTSEC-1"]
    );
    assert_eq!(answer.vulnerabilities.len(), 1);
}

// spec: OSR-24
#[test]
fn the_records_are_returned_in_the_byte_order_of_their_ids() {
    let server = Server::new(|request| {
        if request.path == "/v1/querybatch" {
            answer(request, |_| vec!["RUSTSEC-2", "GHSA-1", "RUSTSEC-10"])
        } else {
            let id = request.path.trim_start_matches("/v1/vulns/").to_owned();
            (200, record(&id))
        }
    });

    let answer = server
        .api()
        .query(&[package("a", "1.0.0")], || at(1_000))
        .expect("the query succeeds");

    let ids: Vec<&str> = answer
        .vulnerabilities
        .iter()
        .map(|v| v.id.as_str())
        .collect();
    assert_eq!(ids, ["GHSA-1", "RUSTSEC-10", "RUSTSEC-2"]);
}

// spec: OSR-28
#[test]
fn a_query_with_a_next_page_token_is_sent_again_with_it() {
    let server = Server::new(|request| {
        if request.path != "/v1/querybatch" {
            let id = request.path.trim_start_matches("/v1/vulns/").to_owned();
            return (200, record(&id));
        }
        let queries = request.json()["queries"].clone();
        if queries[0].get("page_token").is_some() {
            return ok(&json!({"results": [{"vulns": [{"id": "RUSTSEC-2"}]}]}));
        }
        ok(&json!({"results": [
            {"vulns": [{"id": "RUSTSEC-1"}], "next_page_token": "page-2"},
            {},
        ]}))
    });

    let answer = server
        .api()
        .query(&[package("a", "1.0.0"), package("b", "1.0.0")], || {
            at(1_000)
        })
        .expect("the query succeeds");

    let requests = server.requests();
    assert_eq!(
        requests[1].json(),
        json!({"queries": [
            {"package": {"ecosystem": "crates.io", "name": "a"}, "version": "1.0.0", "page_token": "page-2"},
        ]})
    );
    let ids: Vec<&str> = answer
        .vulnerabilities
        .iter()
        .map(|v| v.id.as_str())
        .collect();
    assert_eq!(ids, ["RUSTSEC-1", "RUSTSEC-2"]);
}

// spec: OSR-30
#[test]
fn no_package_sends_no_request() {
    let server = Server::new(|_| (500, Vec::new()));

    let answer = server
        .api()
        .query(&[], || at(1_000))
        .expect("the query succeeds");

    assert_eq!(server.lines().len(), 0);
    assert_eq!(answer.vulnerabilities.len(), 0);
    assert_eq!(answer.freshness.queried_at, at(1_000));
}

// spec: OSR-31
#[test]
fn an_api_answering_503_fails_with_cannot_query() {
    let server = Server::new(|_| (503, b"busy".to_vec()));

    let error = query_error(&server, &[package("a", "1.0.0")]);

    assert!(
        matches!(&error, QueryError::Request { url, .. } if url == &format!("{}/v1/querybatch", server.base)),
        "{error:?}"
    );
    let message = error.to_string();
    assert!(message.contains("cannot query the OSV API"), "{message}");
    assert!(message.contains("503"), "{message}");
}

// spec: OSR-31
#[test]
fn an_unreachable_api_fails_with_cannot_query() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
    let base = format!("http://{}", listener.local_addr().expect("an address"));
    drop(listener);

    let error = Api { base_url: base }
        .query(&[package("a", "1.0.0")], || at(1_000))
        .expect_err("the query fails");

    assert!(matches!(error, QueryError::Request { .. }), "{error:?}");
}

// spec: OSR-31
#[test]
fn an_answer_that_is_not_json_is_refused() {
    let server = Server::new(|_| (200, b"<html>".to_vec()));

    let error = query_error(&server, &[package("a", "1.0.0")]);

    assert!(matches!(error, QueryError::InvalidAnswer(_)), "{error:?}");
    assert!(error.to_string().contains("invalid OSV API answer"));
}

// spec: OSR-31
#[test]
fn an_answer_without_one_result_per_query_is_refused() {
    let server = Server::new(|_| ok(&json!({"results": [{}]})));

    let error = query_error(&server, &[package("a", "1.0.0"), package("b", "1.0.0")]);

    assert!(matches!(error, QueryError::InvalidAnswer(_)), "{error:?}");
}

// spec: OSR-31
#[test]
fn an_unsafe_id_is_refused_before_any_record_request() {
    let server = Server::new(|request| {
        if request.path == "/v1/querybatch" {
            answer(request, |_| vec!["RUSTSEC-1", "../x"])
        } else {
            (200, record("RUSTSEC-1"))
        }
    });

    let error = query_error(&server, &[package("a", "1.0.0")]);

    assert_eq!(error, QueryError::InvalidId("../x".to_owned()));
    assert!(error.to_string().contains("invalid record id \"../x\""));
    assert_eq!(server.lines(), ["POST /v1/querybatch with a body"]);
}

// spec: OSR-31
#[test]
fn the_ids_osv_uses_are_accepted() {
    for id in [
        "GHSA-wcg3-cvx6-7396",
        "PYSEC-2021-1",
        "MAL-2024_1",
        "DSA-5.1:x",
    ] {
        let server = Server::new(move |request| {
            if request.path == "/v1/querybatch" {
                answer(request, |_| vec![id])
            } else {
                (200, record(id))
            }
        });
        let answer = server
            .api()
            .query(&[package("a", "1.0.0")], || at(1_000))
            .unwrap_or_else(|e| panic!("{id}: {e}"));
        assert_eq!(answer.vulnerabilities[0].id, id);
    }
    for id in ["", ".x", "a/b", "a b", "é"] {
        let server = Server::new(move |request| answer(request, |_| vec![id]));
        let error = query_error(&server, &[package("a", "1.0.0")]);
        assert_eq!(error, QueryError::InvalidId(id.to_owned()), "{id:?}");
    }
}

// spec: OSR-31
#[test]
fn an_unreadable_record_fails_naming_its_id() {
    let server = Server::new(|request| {
        if request.path == "/v1/querybatch" {
            answer(request, |_| vec!["RUSTSEC-1"])
        } else {
            let record = json!({"id": "RUSTSEC-1", "affected": [{
                "package": {"ecosystem": "crates.io", "name": "a"},
                "ranges": [{"type": "CALVER", "events": []}],
            }]});
            ok(&record)
        }
    });

    let error = query_error(&server, &[package("a", "1.0.0")]);

    assert!(
        matches!(&error, QueryError::Record { id, cause: Cause::Invalid(_) } if id == "RUSTSEC-1"),
        "{error:?}"
    );
    let message = error.to_string();
    assert!(message.contains("RUSTSEC-1"), "{message}");
    assert!(message.contains("invalid OSV record"), "{message}");
}

// spec: OSR-31
#[test]
fn a_record_request_answering_404_fails_with_cannot_query() {
    let server = Server::new(|request| {
        if request.path == "/v1/querybatch" {
            answer(request, |_| vec!["RUSTSEC-1"])
        } else {
            (404, b"not found".to_vec())
        }
    });

    let error = query_error(&server, &[package("a", "1.0.0")]);

    assert!(
        matches!(&error, QueryError::Request { url, .. } if url.ends_with("/v1/vulns/RUSTSEC-1")),
        "{error:?}"
    );
}

// spec: OSR-28, OSR-31
#[test]
fn a_next_page_token_given_twice_is_refused() {
    let server = Server::new(|_| ok(&json!({"results": [{"next_page_token": "same"}]})));

    let error = query_error(&server, &[package("a", "1.0.0")]);

    assert!(matches!(error, QueryError::InvalidAnswer(_)), "{error:?}");
    assert!(error.to_string().contains("\"same\""), "{error}");
    assert_eq!(server.lines().len(), 2);
}

// spec: OSR-31
#[test]
fn a_record_holding_another_id_is_refused() {
    let server = Server::new(|request| {
        if request.path == "/v1/querybatch" {
            answer(request, |_| vec!["GHSA-a"])
        } else {
            (200, record("RUSTSEC-b"))
        }
    });

    let error = query_error(&server, &[package("a", "1.0.0")]);

    assert!(
        matches!(&error, QueryError::Record { id, cause: Cause::Invalid(reason) } if id == "GHSA-a" && reason.contains("\"RUSTSEC-b\"")),
        "{error:?}"
    );
}

// spec: OSR-36, OSR-31
#[test]
fn a_record_of_the_api_with_a_blank_id_is_refused_as_blank() {
    let server = Server::new(|request| {
        if request.path == "/v1/querybatch" {
            answer(request, |_| vec!["GHSA-a"])
        } else {
            (200, record(" "))
        }
    });

    let error = query_error(&server, &[package("a", "1.0.0")]);

    assert!(
        matches!(&error, QueryError::Record { id, cause: Cause::Invalid(reason) } if id == "GHSA-a" && reason.contains("`id` is empty or only whitespace")),
        "{error:?}"
    );
}
