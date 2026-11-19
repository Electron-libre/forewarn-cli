//! A loopback endpoint in plain HTTP is reached directly, never through the proxy the environment names (UPL-13). One
//! test alone in its binary: it sets the proxy variables of its process.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;

use forewarn_upload::{Endpoint, Stored, Token, upload};

/// A loopback server answering every request with `reply`, recording each request line.
fn serve(reply: String) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
    let base = format!("http://{}", listener.local_addr().expect("an address"));
    let lines = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&lines);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            let _ = reader.read_line(&mut line);
            seen.lock()
                .expect("the lines")
                .push(line.trim_end().to_owned());
            // The head and a small body, read before answering.
            let mut length = 0;
            loop {
                let mut header = String::new();
                if reader.read_line(&mut header).unwrap_or(0) == 0 || header.trim_end().is_empty() {
                    break;
                }
                if let Some(value) = header.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse().unwrap_or(0);
                }
            }
            let mut body = vec![0; length];
            let _ = std::io::Read::read_exact(&mut reader, &mut body);
            let _ = reader.into_inner().write_all(reply.as_bytes());
        }
    });
    (base, lines)
}

fn answer(status: u16, body: &str) -> String {
    format!(
        "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

// spec: UPL-13
#[test]
fn a_loopback_endpoint_in_plain_http_is_not_reached_through_a_proxy() {
    let receipt = r#"{"product": "p", "version": "1", "spec_version": "1.6", "components": 0,
        "received_at": "2026-11-19T10:00:00Z", "first_uploaded_at": "2026-11-19T10:00:00Z", "warnings": []}"#;
    let (service, service_lines) = serve(answer(201, receipt));
    let (proxy, proxy_lines) = serve(answer(502, "proxy"));
    for name in [
        "ALL_PROXY",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "all_proxy",
        "http_proxy",
        "https_proxy",
    ] {
        // SAFETY: the only test of this binary, so no other thread reads the environment.
        unsafe { std::env::set_var(name, &proxy) };
    }
    for name in ["NO_PROXY", "no_proxy"] {
        // SAFETY: as above.
        unsafe { std::env::remove_var(name) };
    }
    let endpoint = Endpoint::parse(&service).expect("an endpoint");
    let token = Token::new("fw_secret".to_owned()).expect("a token");
    let stored = upload(&endpoint, &token, "p", "1", b"{}").expect("stored");
    assert!(matches!(stored, Stored::Created(_)), "{stored:?}");
    assert!(proxy_lines.lock().expect("the lines").is_empty());
    assert_eq!(service_lines.lock().expect("the lines").len(), 1);
}
