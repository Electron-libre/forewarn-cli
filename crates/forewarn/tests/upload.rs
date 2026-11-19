//! `forewarn upload` sending an SBOM to a Forewarn service (`specs/cli-upload.md`), against a loopback HTTP server:
//! no test needs the network.

mod common;

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;

use common::{Run, bom, run_with};
use serde_json::{Value, json};
use tempfile::TempDir;

const TOKEN: &str = "fw_secret";

/// A request the service received: its method, its path, its `Authorization` header and its body.
#[derive(Clone, Debug)]
struct Request {
    method: String,
    path: String,
    authorization: Option<String>,
    body: Vec<u8>,
}

/// A loopback HTTP server giving the same answer to every request, and recording each request.
struct Service {
    base: String,
    requests: Arc<Mutex<Vec<Request>>>,
}

impl Service {
    fn answering(status: u16, body: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        let base = format!("http://{}", listener.local_addr().expect("an address"));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&requests);
        let reply = format!(
            "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let mut reader = BufReader::new(stream);
                let mut line = String::new();
                reader.read_line(&mut line).expect("a request line");
                let mut parts = line.split(' ');
                let method = parts.next().unwrap_or_default().to_owned();
                let path = parts.next().unwrap_or_default().to_owned();
                let (mut length, mut authorization, mut continues) = (0, None, false);
                loop {
                    let mut header = String::new();
                    reader.read_line(&mut header).expect("a header");
                    let Some((name, value)) = header.trim_end().split_once(':') else {
                        break;
                    };
                    match name.to_ascii_lowercase().as_str() {
                        "content-length" => length = value.trim().parse().expect("a length"),
                        "authorization" => authorization = Some(value.trim().to_owned()),
                        "expect" => continues = value.trim() == "100-continue",
                        _ => {}
                    }
                }
                if continues {
                    let _ = reader.get_mut().write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
                }
                let mut body = vec![0; length];
                reader.read_exact(&mut body).expect("the body");
                seen.lock().expect("the requests").push(Request {
                    method,
                    path,
                    authorization,
                    body,
                });
                let _ = reader.into_inner().write_all(reply.as_bytes());
            }
        });
        Self { base, requests }
    }

    fn requests(&self) -> Vec<Request> {
        self.requests.lock().expect("the requests").clone()
    }
}

/// A loopback endpoint that closes each connection without an answer, kept bound for the whole test so that no other
/// server of a test running alongside takes its port.
fn closing() -> (TcpListener, String) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
    let base = format!("http://{}", listener.local_addr().expect("an address"));
    let accepting = listener.try_clone().expect("a listener");
    thread::spawn(move || {
        for stream in accepting.incoming() {
            drop(stream);
        }
    });
    (listener, base)
}

/// A receipt of `components` components carrying `warnings`.
fn receipt(components: u64, warnings: &Value) -> String {
    json!({
        "product": "acme-gateway", "version": "2.4.0", "spec_version": "1.6", "components": components,
        "received_at": "2026-11-19T10:00:00.123Z", "first_uploaded_at": "2026-11-01T08:00:00Z",
        "warnings": warnings,
    })
    .to_string()
}

/// A 1.6 SBOM of one component describing `product`, as `metadata.component`, unless `None`.
fn sbom_of(product: Option<Value>) -> Vec<u8> {
    let mut document: Value = serde_json::from_slice(&bom(
        "1.6",
        &json!([{"type": "library", "name": "time", "version": "0.1.43"}]),
    ))
    .expect("JSON");
    if let Some(product) = product {
        document["metadata"] = json!({ "component": product });
    }
    serde_json::to_vec_pretty(&document).expect("the SBOM serializes")
}

fn gateway() -> Vec<u8> {
    sbom_of(Some(
        json!({"type": "application", "name": "acme-gateway", "version": "2.4.0"}),
    ))
}

/// Runs `forewarn upload <args>` with the token set, `FOREWARN_ENDPOINT` removed unless given in `env`.
fn upload(args: &[&str], stdin: Option<&[u8]>, env: &[(&str, Option<&str>)]) -> Run {
    let mut all = vec![("FOREWARN_ENDPOINT", None), ("FOREWARN_TOKEN", Some(TOKEN))];
    all.extend_from_slice(env);
    let args: Vec<&str> = ["upload"].iter().chain(args).copied().collect();
    run_with(&args, stdin, &all)
}

/// Uploads the SBOM `sbom`, written to a file, to `endpoint`.
fn upload_file(endpoint: &str, sbom: &[u8], extra: &[&str]) -> Run {
    let dir = TempDir::new().expect("a temp dir");
    let path = dir.path().join("sbom.json");
    fs::write(&path, sbom).expect("the SBOM is written");
    let path = path.to_str().expect("a UTF-8 path");
    let mut args = vec!["--endpoint", endpoint];
    args.extend_from_slice(extra);
    args.push(path);
    upload(&args, None, &[])
}

// spec: CUP-H1, CUP-1, CUP-2, CUP-7, CUP-8, CUP-12, CUP-9
#[test]
fn an_sbom_is_uploaded_as_is_for_the_product_it_describes() {
    let service = Service::answering(201, &receipt(3, &json!([])));
    let sbom = gateway();
    let dir = TempDir::new().expect("a temp dir");
    let path = dir.path().join("sbom.json");
    fs::write(&path, &sbom).expect("the SBOM is written");
    let run = upload(
        &[path.to_str().expect("a UTF-8 path")],
        None,
        &[("FOREWARN_ENDPOINT", Some(&service.base))],
    );
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert_eq!(run.stderr, "");
    let requests = service.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, "PUT");
    assert_eq!(
        requests[0].path,
        "/api/v1/products/acme-gateway/versions/2.4.0/sbom"
    );
    assert_eq!(
        requests[0].authorization.as_deref(),
        Some("Bearer fw_secret")
    );
    assert_eq!(requests[0].body, sbom);
    for part in [
        service.base.as_str(),
        "acme-gateway",
        "2.4.0",
        "new version",
        "3 components",
        "2026-11-19T10:00:00.123Z",
    ] {
        assert!(run.stdout.contains(part), "{part}: {}", run.stdout);
    }
    assert!(!run.stdout.contains(TOKEN));
}

// spec: CUP-1, CUP-12
#[test]
fn a_replaced_sbom_is_reported_with_the_warnings_of_the_receipt() {
    let service = Service::answering(
        200,
        &receipt(
            3,
            &json!([{"code": "spec_version_below_minimum", "message": "1.5 is below 1.6"}]),
        ),
    );
    let run = upload_file(&service.base, &gateway(), &[]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    for part in ["replaced", "spec_version_below_minimum", "1.5 is below 1.6"] {
        assert!(run.stdout.contains(part), "{part}: {}", run.stdout);
    }
    assert!(!run.stdout.contains("new version"), "{}", run.stdout);
}

// spec: CUP-3
#[test]
fn the_options_override_the_product_name_and_the_version_each_alone() {
    let service = Service::answering(201, &receipt(1, &json!([])));
    let run = upload_file(&service.base, &gateway(), &["--product-version", "2.4.1"]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    let run = upload_file(&service.base, &gateway(), &["--product", "@acme/edge"]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    let paths: Vec<String> = service.requests().into_iter().map(|r| r.path).collect();
    assert_eq!(
        paths,
        [
            "/api/v1/products/acme-gateway/versions/2.4.1/sbom",
            "/api/v1/products/%40acme%2Fedge/versions/2.4.0/sbom",
        ]
    );
}

// spec: CUP-4
#[test]
fn an_sbom_piped_is_sent_as_read() {
    let service = Service::answering(201, &receipt(1, &json!([])));
    let sbom = gateway();
    let run = upload(&["--endpoint", &service.base, "-"], Some(&sbom), &[]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert_eq!(service.requests()[0].body, sbom);
}

// spec: CUP-7
#[test]
fn the_endpoint_option_wins_over_the_environment_and_an_empty_variable_is_unset() {
    let service = Service::answering(201, &receipt(1, &json!([])));
    let (_listener, unreachable) = closing();
    let run = upload(
        &["--endpoint", &service.base, "-"],
        Some(&gateway()),
        &[("FOREWARN_ENDPOINT", Some(&unreachable))],
    );
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert_eq!(service.requests().len(), 1);

    let run = upload(&["-"], Some(&gateway()), &[("FOREWARN_ENDPOINT", Some(""))]);
    assert_eq!(run.code, 2, "{}", run.stderr);
    assert!(run.stderr.contains("FOREWARN_ENDPOINT"), "{}", run.stderr);
}

// spec: CUP-7, CUP-9, CUP-10
#[test]
fn an_endpoint_the_adapter_refuses_is_a_usage_error_naming_it() {
    let run = upload(
        &["--endpoint", "http://example.com", "missing.json"],
        None,
        &[],
    );
    assert_eq!(run.code, 2, "{}", run.stderr);
    assert!(run.stderr.contains("http://example.com"), "{}", run.stderr);
    assert!(!run.stderr.contains("missing.json"), "{}", run.stderr);
}

// spec: CUP-8, CUP-9, CUP-10
#[test]
fn a_missing_or_refused_token_is_a_usage_error_before_the_sbom_is_read() {
    let service = Service::answering(201, &receipt(1, &json!([])));
    for token in [None, Some("fw secret"), Some("")] {
        let run = upload(
            &["--endpoint", &service.base, "missing.json"],
            None,
            &[("FOREWARN_TOKEN", token)],
        );
        assert_eq!(run.code, 2, "{token:?}: {}", run.stderr);
        assert!(run.stderr.contains("FOREWARN_TOKEN"), "{}", run.stderr);
        assert!(!run.stderr.contains("missing.json"), "{}", run.stderr);
    }
    assert!(service.requests().is_empty());
}

// spec: CUP-2, CUP-9, CUP-10, CUP-11
#[test]
fn an_sbom_the_adapter_refuses_is_not_sent() {
    let service = Service::answering(201, &receipt(1, &json!([])));
    let run = upload(
        &["--endpoint", &service.base, "-"],
        Some(&bom("1.2", &json!([]))),
        &[],
    );
    assert_eq!(run.code, 3, "{}", run.stderr);
    assert!(run.stderr.contains("standard input"), "{}", run.stderr);
    assert_eq!(run.stdout, "");
    assert!(service.requests().is_empty());
}

// spec: CUP-9, CUP-11
#[test]
fn a_missing_product_name_or_version_names_the_option_to_give() {
    let service = Service::answering(201, &receipt(1, &json!([])));
    let no_version = sbom_of(Some(json!({"type": "application", "name": "acme-gateway"})));
    let blank_version = sbom_of(Some(
        json!({"type": "application", "name": "acme-gateway", "version": " "}),
    ));
    let blank_name = sbom_of(Some(
        json!({"type": "application", "name": "", "version": "2.4.0"}),
    ));
    for (sbom, option) in [
        (no_version, "--product-version"),
        (blank_version, "--product-version"),
        (blank_name, "--product"),
        (sbom_of(None), "--product"),
    ] {
        let run = upload_file(&service.base, &sbom, &[]);
        assert_eq!(run.code, 2, "{option}: {}", run.stderr);
        assert!(run.stderr.contains(option), "{}", run.stderr);
        assert_eq!(run.stderr.lines().count(), 1, "{}", run.stderr);
        assert_eq!(run.stdout, "");
    }
    let run = upload_file(
        &service.base,
        &sbom_of(None),
        &["--product", "acme-gateway", "--product-version", "1.0"],
    );
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert_eq!(service.requests().len(), 1);
}

// spec: CUP-9, CUP-10
#[test]
fn a_name_or_a_size_the_contract_refuses_exits_with_10_and_sends_nothing() {
    let service = Service::answering(201, &receipt(1, &json!([])));
    let run = upload_file(&service.base, &gateway(), &["--product", ".."]);
    assert_eq!(run.code, 10, "{}", run.stderr);
    assert!(run.stderr.contains("product name"), "{}", run.stderr);

    let mut large = gateway();
    // White space after the document keeps it a readable SBOM.
    large.resize(10 * 1024 * 1024 + 1, b' ');
    let run = upload_file(&service.base, &large, &[]);
    assert_eq!(run.code, 10, "{}", run.stderr);
    assert!(run.stderr.contains("10485761"), "{}", run.stderr);

    // The size first: a file over the limit is refused as such, never read as CycloneDX.
    let run = upload_file(&service.base, &vec![b'x'; 10 * 1024 * 1024 + 3], &[]);
    assert_eq!(run.code, 10, "{}", run.stderr);
    assert!(run.stderr.contains("10485763"), "{}", run.stderr);
    let run = upload(
        &["--endpoint", &service.base, "-"],
        Some(&vec![b'x'; 10 * 1024 * 1024 + 3]),
        &[],
    );
    assert_eq!(run.code, 10, "{}", run.stderr);
    assert!(run.stderr.contains("10485763"), "{}", run.stderr);
    assert!(service.requests().is_empty());
}

// spec: CUP-H2, CUP-6, CUP-9, CUP-11, CUP-14
#[test]
fn refused_credentials_exit_with_9_naming_the_endpoint_and_no_token() {
    let service = Service::answering(401, r#"{"error": "unauthorized"}"#);
    let run = upload_file(&service.base, &gateway(), &[]);
    assert_eq!(run.code, 9, "{}", run.stderr);
    assert_eq!(run.stdout, "");
    assert_eq!(run.stderr.lines().count(), 1, "{}", run.stderr);
    assert!(run.stderr.contains(&service.base), "{}", run.stderr);
    assert!(run.stderr.contains("credentials"), "{}", run.stderr);
    assert!(!run.stderr.contains(TOKEN), "{}", run.stderr);
}

// spec: CUP-6, CUP-9, CUP-11
#[test]
fn each_failure_of_the_upload_exits_with_its_own_code() {
    let (_listener, unreachable) = closing();
    let run = upload_file(&unreachable, &gateway(), &[]);
    assert_eq!(run.code, 8, "{}", run.stderr);

    let service = Service::answering(
        422,
        r#"{"error": "unreadable_sbom", "message": "not CycloneDX"}"#,
    );
    let run = upload_file(&service.base, &gateway(), &[]);
    assert_eq!(run.code, 10, "{}", run.stderr);
    for part in ["unreadable_sbom", "not CycloneDX"] {
        assert!(run.stderr.contains(part), "{part}: {}", run.stderr);
    }

    let service = Service::answering(502, "<html>bad gateway</html>");
    let run = upload_file(&service.base, &gateway(), &[]);
    assert_eq!(run.code, 11, "{}", run.stderr);
    assert!(run.stderr.contains("502"), "{}", run.stderr);
    assert_eq!(run.stdout, "");
}

// spec: CUP-14
#[test]
fn the_token_echoed_by_the_service_is_never_printed() {
    let service = Service::answering(
        400,
        &json!({"error": "unreadable_body", "message": format!("bad {TOKEN}")}).to_string(),
    );
    let run = upload_file(&service.base, &gateway(), &[]);
    assert_eq!(run.code, 10, "{}", run.stderr);
    assert!(run.stderr.contains("***"), "{}", run.stderr);
    assert!(!run.stderr.contains(TOKEN), "{}", run.stderr);
}

// spec: CUP-13
#[test]
fn the_values_of_the_sbom_and_of_the_service_are_printed_escaped() {
    let service = Service::answering(
        200,
        &receipt(
            1,
            &json!([{"code": "odd\u{1b}[31m", "message": "line\nforged"}]),
        ),
    );
    let sbom = sbom_of(Some(
        json!({"type": "application", "name": "gate\u{202e}way", "version": "2.4.0"}),
    ));
    let run = upload_file(&service.base, &sbom, &[]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    for part in ["odd\\u{1b}[31m", "line\\nforged", "gate\\u{202e}way"] {
        assert!(run.stdout.contains(part), "{part}: {}", run.stdout);
    }
    assert!(!run.stdout.contains('\u{1b}'), "{}", run.stdout);
}

// spec: CUP-15
#[test]
fn a_path_that_cannot_be_read_is_named_escaped() {
    let service = Service::answering(201, &receipt(1, &json!([])));
    let run = upload(
        &["--endpoint", &service.base, "no\u{1b}such.json"],
        None,
        &[],
    );
    assert_eq!(run.code, 3, "{}", run.stderr);
    assert!(run.stderr.contains("no\\u{1b}such.json"), "{}", run.stderr);
    assert!(service.requests().is_empty());
}

// spec: CUP-H3, CUP-5, CUP-8
#[test]
fn a_dry_run_prints_what_would_be_sent_and_sends_nothing_without_a_token() {
    let service = Service::answering(201, &receipt(1, &json!([])));
    let sbom = gateway();
    let dir = TempDir::new().expect("a temp dir");
    let path = dir.path().join("sbom.json");
    fs::write(&path, &sbom).expect("the SBOM is written");
    let run = upload(
        &[
            "--dry-run",
            "--endpoint",
            &service.base,
            path.to_str().expect("a UTF-8 path"),
        ],
        None,
        &[("FOREWARN_TOKEN", None)],
    );
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert_eq!(run.stderr, "");
    let size = sbom.len().to_string();
    for part in [
        service.base.as_str(),
        "acme-gateway",
        "2.4.0",
        size.as_str(),
    ] {
        assert!(run.stdout.contains(part), "{part}: {}", run.stdout);
    }
    assert!(service.requests().is_empty());
}

// spec: CUP-5, CUP-9
#[test]
fn a_dry_run_refuses_what_the_upload_would_refuse() {
    let run = upload(
        &["--dry-run", "--endpoint", "http://example.com", "-"],
        Some(&gateway()),
        &[("FOREWARN_TOKEN", None)],
    );
    assert_eq!(run.code, 2, "{}", run.stderr);
    let service = Service::answering(201, &receipt(1, &json!([])));
    let run = upload(
        &[
            "--dry-run",
            "--endpoint",
            &service.base,
            "--product",
            "..",
            "-",
        ],
        Some(&gateway()),
        &[],
    );
    assert_eq!(run.code, 10, "{}", run.stderr);
    assert!(run.stderr.contains("product name"), "{}", run.stderr);
    assert!(service.requests().is_empty());
}
