//! The upload of an SBOM (`specs/sbom-upload.md`), against a loopback HTTP server: no test needs the network.

use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;

use forewarn_api::{ErrorCode, Name, NameProblem};
use forewarn_upload::{Endpoint, MAX_SBOM_BYTES, Stored, Token, UploadError, upload};

const TOKEN: &str = "fw_secret";

/// A request the server received.
#[derive(Clone, Debug)]
struct Request {
    method: String,
    path: String,
    /// Each header, its name in lower case.
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(header, _)| header == name)
            .map(|(_, value)| value.as_str())
    }
}

/// A loopback HTTP server giving the same answer to every request, and recording each request.
struct Server {
    base: String,
    requests: Arc<Mutex<Vec<Request>>>,
}

/// When a server answers a request asking `Expect: 100-continue` (UPL-14).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// `100 Continue`, then the answer once the body is read, as servers do.
    Continue,
    /// No `100 Continue`: the answer once the body is read.
    NeverContinue,
    /// The answer as soon as the head is read, then the connection closed with the body unread.
    AnswerFirst,
    /// `417 Expectation Failed` to a request asking it, the answer to any other once its body is read.
    RefuseExpectation,
}

impl Server {
    fn answering(status: u16, headers: &[(&str, &str)], body: &str) -> Self {
        Self::start(Mode::Continue, status, headers, body)
    }

    fn start(mode: Mode, status: u16, headers: &[(&str, &str)], body: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        let base = format!("http://{}", listener.local_addr().expect("an address"));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&requests);
        let mut reply = format!(
            "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n",
            body.len()
        );
        for (name, value) in headers {
            write!(reply, "{name}: {value}\r\n").expect("a header");
        }
        reply.push_str("\r\n");
        reply.push_str(body);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let mut reader = BufReader::new(stream);
                let mut line = String::new();
                reader.read_line(&mut line).expect("a request line");
                let mut parts = line.split(' ');
                let method = parts.next().unwrap_or_default().to_owned();
                let path = parts.next().unwrap_or_default().to_owned();
                let mut headers = Vec::new();
                loop {
                    let mut header = String::new();
                    reader.read_line(&mut header).expect("a header");
                    let header = header.trim_end();
                    if header.is_empty() {
                        break;
                    }
                    let (name, value) = header.split_once(':').expect("a header");
                    headers.push((name.to_ascii_lowercase(), value.trim().to_owned()));
                }
                let length = headers
                    .iter()
                    .find(|(name, _)| name == "content-length")
                    .map_or(0, |(_, value)| value.parse().expect("a length"));
                let expects = headers
                    .iter()
                    .any(|(name, value)| name == "expect" && value == "100-continue");
                let mut body = Vec::new();
                match mode {
                    Mode::AnswerFirst => {}
                    Mode::RefuseExpectation if expects => {
                        seen.lock().expect("the requests").push(Request {
                            method,
                            path,
                            headers,
                            body,
                        });
                        let _ = reader.into_inner().write_all(
                            b"HTTP/1.1 417 Expectation Failed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        );
                        continue;
                    }
                    Mode::Continue | Mode::NeverContinue | Mode::RefuseExpectation => {
                        if mode == Mode::Continue && expects {
                            let _ = reader.get_mut().write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
                        }
                        body.resize(length, 0);
                        reader.read_exact(&mut body).expect("the body");
                    }
                }
                seen.lock().expect("the requests").push(Request {
                    method,
                    path,
                    headers,
                    body,
                });
                let mut stream = reader.into_inner();
                let _ = stream.write_all(reply.as_bytes());
            }
        });
        Self { base, requests }
    }

    fn requests(&self) -> Vec<Request> {
        self.requests.lock().expect("the requests").clone()
    }
}

fn receipt(components: u64) -> String {
    format!(
        r#"{{"product": "@acme/gateway", "version": "2.4.0", "spec_version": "1.6", "components": {components},
            "received_at": "2026-11-19T10:00:00.123Z", "first_uploaded_at": "2026-11-19T10:00:00.123Z",
            "warnings": []}}"#
    )
}

fn token() -> Token {
    Token::new(TOKEN.to_owned()).expect("a token")
}

fn send(endpoint: &str, sbom: &[u8]) -> Result<Stored, UploadError> {
    let endpoint = Endpoint::parse(endpoint).expect("an endpoint");
    upload(&endpoint, &token(), "@acme/gateway", "2.4.0", sbom)
}

/// The error of an upload to a server answering `status` with `body`, checked to hold no token (UPL-4).
fn failed(status: u16, body: &str) -> (Server, UploadError) {
    let server = Server::answering(status, &[], body);
    let error = send(&server.base, b"{}").expect_err("the upload fails");
    assert_holds_no_token(&error);
    (server, error)
}

fn assert_holds_no_token(error: &UploadError) {
    let text = format!("{error} {error:?}");
    assert!(!text.contains(TOKEN), "{text}");
}

// spec: UPL-H1, UPL-1, UPL-5, UPL-9
#[test]
fn an_sbom_is_sent_as_is_with_the_token_and_its_receipt_read() {
    let server = Server::answering(201, &[], &receipt(3));
    let sbom = br#"{"bomFormat": "CycloneDX", "specVersion": "1.6"}"#;
    let stored = send(&format!("{}/forewarn/", server.base), sbom).expect("stored");
    let Stored::Created(receipt) = stored else {
        panic!("a new version: {stored:?}")
    };
    assert_eq!(receipt.components, 3);
    let requests = server.requests();
    assert_eq!(requests.len(), 1, "{requests:?}");
    let request = &requests[0];
    assert_eq!(request.method, "PUT");
    assert_eq!(
        request.path,
        "/forewarn/api/v1/products/%40acme%2Fgateway/versions/2.4.0/sbom"
    );
    assert_eq!(request.header("authorization"), Some("Bearer fw_secret"));
    assert_eq!(
        request.header("content-type"),
        Some("application/vnd.cyclonedx+json")
    );
    assert_eq!(request.header("expect"), Some("100-continue"));
    assert_eq!(request.body, sbom);
}

// spec: UPL-1, UPL-9
#[test]
fn an_answer_200_is_a_replaced_sbom() {
    let server = Server::answering(200, &[], &receipt(5));
    let stored = send(&server.base, b"{}").expect("stored");
    assert!(
        matches!(&stored, Stored::Replaced(receipt) if receipt.components == 5),
        "{stored:?}"
    );
}

// spec: UPL-H2, UPL-3, UPL-4, UPL-9
#[test]
fn an_answer_401_is_credentials_refused_naming_the_endpoint() {
    let (server, error) = failed(401, r#"{"error": "unauthorized"}"#);
    let UploadError::CredentialsRefused { endpoint, refusal } = &error else {
        panic!("credentials refused: {error:?}")
    };
    assert_eq!(endpoint, &server.base);
    assert_eq!(refusal.status, 401);
    assert_eq!(refusal.body.error, ErrorCode::Unauthorized);
    assert!(error.to_string().contains(&server.base), "{error}");
}

// spec: UPL-9
#[test]
fn an_answer_403_is_credentials_refused() {
    let (_, error) = failed(403, r#"{"error": "forbidden"}"#);
    assert!(
        matches!(&error, UploadError::CredentialsRefused { refusal, .. } if refusal.status == 403),
        "{error:?}"
    );
}

// spec: UPL-3, UPL-9
#[test]
fn another_refusal_is_upload_refused_with_its_code_and_message() {
    let (server, error) = failed(
        422,
        r#"{"error": "unreadable_sbom", "message": "not CycloneDX"}"#,
    );
    let UploadError::Refused { endpoint, refusal } = &error else {
        panic!("upload refused: {error:?}")
    };
    assert_eq!(endpoint, &server.base);
    assert_eq!(refusal.status, 422);
    assert_eq!(refusal.body.error, ErrorCode::UnreadableSbom);
    assert_eq!(refusal.body.message.as_deref(), Some("not CycloneDX"));
    let text = error.to_string();
    assert!(
        text.contains("unreadable_sbom") && text.contains("not CycloneDX"),
        "{text}"
    );

    let (_, error) = failed(503, r#"{"error": "unavailable"}"#);
    assert!(
        matches!(&error, UploadError::Refused { refusal, .. } if refusal.body.error == ErrorCode::Unavailable),
        "{error:?}"
    );
}

// spec: UPL-3, UPL-9
#[test]
fn a_body_that_cannot_be_read_is_an_unreadable_answer_naming_its_status() {
    let (server, error) = failed(502, "<html><body>Bad gateway</body></html>");
    let UploadError::UnreadableAnswer {
        endpoint, status, ..
    } = &error
    else {
        panic!("unreadable answer: {error:?}")
    };
    assert_eq!((endpoint, *status), (&server.base, 502));
    assert!(error.to_string().contains("502"), "{error}");
}

// spec: UPL-9
#[test]
fn an_answer_over_one_mebibyte_is_unreadable() {
    let message = "x".repeat(1024 * 1024);
    let (_, error) = failed(
        422,
        &format!(r#"{{"error": "unreadable_sbom", "message": "{message}"}}"#),
    );
    assert!(
        matches!(&error, UploadError::UnreadableAnswer { status: 422, .. }),
        "{error:?}"
    );
}

// spec: UPL-3, UPL-9
#[test]
fn an_endpoint_where_nothing_listens_is_unreachable() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
    let base = format!("http://{}", listener.local_addr().expect("an address"));
    drop(listener);
    let error = send(&base, b"{}").expect_err("the upload fails");
    assert_holds_no_token(&error);
    let UploadError::Unreachable { endpoint, .. } = &error else {
        panic!("unreachable: {error:?}")
    };
    assert_eq!(endpoint, &base);
    assert!(error.to_string().contains(&base), "{error}");
}

// spec: UPL-10
#[test]
fn a_redirect_is_not_followed() {
    let target = Server::answering(201, &[], &receipt(1));
    let location = format!("{}/elsewhere", target.base);
    let server = Server::answering(307, &[("Location", &location)], "");
    let error = send(&server.base, b"{}").expect_err("the upload fails");
    assert!(
        matches!(&error, UploadError::UnreadableAnswer { status: 307, .. }),
        "{error:?}"
    );
    assert!(target.requests().is_empty(), "{:?}", target.requests());
    assert_eq!(server.requests().len(), 1);
}

// spec: UPL-11
#[test]
fn an_error_names_the_endpoint_without_a_trailing_slash() {
    let server = Server::answering(401, &[], r#"{"error": "unauthorized"}"#);
    let error = send(&format!("{}/", server.base), b"{}").expect_err("the upload fails");
    assert!(
        matches!(&error, UploadError::CredentialsRefused { endpoint, .. } if *endpoint == server.base),
        "{error:?}"
    );
}

// spec: UPL-12, UPL-4
#[test]
fn the_token_echoed_by_the_service_is_written_as_stars() {
    let (_, error) = failed(
        400,
        r#"{"error": "fw_secret_code", "message": "the token fw_secret is unknown"}"#,
    );
    let UploadError::Refused { refusal, .. } = &error else {
        panic!("upload refused: {error:?}")
    };
    assert_eq!(
        refusal.body.message.as_deref(),
        Some("the token *** is unknown")
    );
    assert_eq!(refusal.body.error.as_str(), "***_code");

    let (_, error) = failed(201, r#"{"product": ["fw_secret"]}"#);
    assert!(
        matches!(&error, UploadError::UnreadableAnswer { status: 201, .. }),
        "{error:?}"
    );
}

// spec: UPL-8
#[test]
fn an_sbom_over_ten_mebibytes_is_refused_before_anything_is_sent() {
    assert_eq!(MAX_SBOM_BYTES, 10_485_760);
    let server = Server::answering(201, &[], &receipt(0));
    let limit = usize::try_from(MAX_SBOM_BYTES).expect("a size");
    send(&server.base, &vec![b' '; limit]).expect("the limit is sent");
    let error = send(&server.base, &vec![b' '; limit + 1]).expect_err("refused");
    assert!(
        matches!(&error, UploadError::TooLarge { size: 10_485_761 }),
        "{error:?}"
    );
    assert!(error.to_string().contains("10485761"), "{error}");
    assert_eq!(server.requests().len(), 1);
}

// spec: UPL-8
#[test]
fn a_name_the_contract_refuses_is_refused_before_anything_is_sent() {
    let server = Server::answering(201, &[], &receipt(0));
    let endpoint = Endpoint::parse(&server.base).expect("an endpoint");
    let error = upload(&endpoint, &token(), "..", "2.4.0", b"{}").expect_err("refused");
    let UploadError::InvalidName(invalid) = &error else {
        panic!("invalid name: {error:?}")
    };
    assert_eq!(
        (invalid.name, invalid.problem),
        (Name::Product, NameProblem::DotSegment)
    );
    assert!(error.to_string().contains("product name"), "{error}");
    assert!(server.requests().is_empty());
}

/// An SBOM of 8 MiB, more than a connection buffers before the service reads it.
fn large_sbom() -> Vec<u8> {
    vec![b' '; 8 * 1024 * 1024]
}

// spec: UPL-14, UPL-9, UPL-4
#[test]
fn credentials_refused_before_the_body_is_read_are_told() {
    let server = Server::start(Mode::AnswerFirst, 401, &[], r#"{"error": "unauthorized"}"#);
    let error = send(&server.base, &large_sbom()).expect_err("the upload fails");
    assert_holds_no_token(&error);
    assert!(
        matches!(&error, UploadError::CredentialsRefused { refusal, .. } if refusal.status == 401),
        "{error:?}"
    );
}

// spec: UPL-14, UPL-9
#[test]
fn an_upload_refused_before_the_body_is_read_is_told() {
    let server = Server::start(Mode::AnswerFirst, 413, &[], r#"{"error": "too_large"}"#);
    let error = send(&server.base, &large_sbom()).expect_err("the upload fails");
    assert!(
        matches!(&error, UploadError::Refused { refusal, .. }
            if refusal.status == 413 && refusal.body.error == ErrorCode::TooLarge),
        "{error:?}"
    );
}

// spec: UPL-14, UPL-1
#[test]
fn a_service_that_never_answers_100_continue_receives_the_sbom() {
    let server = Server::start(Mode::NeverContinue, 201, &[], &receipt(2));
    let sbom = br#"{"bomFormat": "CycloneDX"}"#;
    let stored = send(&server.base, sbom).expect("stored");
    assert!(
        matches!(&stored, Stored::Created(receipt) if receipt.components == 2),
        "{stored:?}"
    );
    let requests = server.requests();
    assert_eq!(requests.len(), 1, "{requests:?}");
    assert_eq!(requests[0].body, sbom);
}

// spec: UPL-15, UPL-1
#[test]
fn a_request_refusing_the_expectation_is_sent_again_without_it() {
    let server = Server::start(Mode::RefuseExpectation, 201, &[], &receipt(4));
    let sbom = br#"{"bomFormat": "CycloneDX"}"#;
    let stored = send(&server.base, sbom).expect("stored");
    assert!(
        matches!(&stored, Stored::Created(receipt) if receipt.components == 4),
        "{stored:?}"
    );
    let requests = server.requests();
    assert_eq!(requests.len(), 2, "{requests:?}");
    assert_eq!(requests[0].header("expect"), Some("100-continue"));
    assert_eq!(requests[1].header("expect"), None);
    assert_eq!(
        requests[1].header("authorization"),
        Some("Bearer fw_secret")
    );
    assert_eq!(requests[1].body, sbom);
}

// spec: UPL-15, UPL-9
#[test]
fn a_second_417_is_read_as_any_answer() {
    let server = Server::start(
        Mode::AnswerFirst,
        417,
        &[],
        "<html>Expectation Failed</html>",
    );
    let error = send(&server.base, b"{}").expect_err("the upload fails");
    assert!(
        matches!(&error, UploadError::UnreadableAnswer { status: 417, .. }),
        "{error:?}"
    );
    assert_eq!(server.requests().len(), 2);
}
