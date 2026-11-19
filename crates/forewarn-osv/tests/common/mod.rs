//! What the tests of fetching share: a loopback HTTP server, zip archives of the fixtures, an `Archives` pointed at
//! the server.

// `expect` would fail in the test crates that use every helper.
#![allow(dead_code, reason = "each test crate uses a part of the helpers")]

use std::collections::HashMap;
use std::fs;
use std::io::{Cursor, Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime};

use forewarn_osv::fetch::{Archives, FetchError, Refresh, Snapshot};
use zip::ZipWriter;
use zip::write::SimpleFileOptions;

/// A response of the loopback server: status, headers, body.
#[derive(Clone)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(&'static str, &'static str)>,
    pub body: Vec<u8>,
    /// How long the server waits before answering.
    pub delay: Duration,
}

pub fn ok(body: Vec<u8>) -> Response {
    Response {
        status: 200,
        headers: Vec::new(),
        body,
        delay: Duration::ZERO,
    }
}

/// A loopback HTTP server answering each path from a table, 404 otherwise, and recording each request line.
pub struct Server {
    pub base: String,
    pub requests: Arc<Mutex<Vec<String>>>,
    pub routes: Arc<Mutex<HashMap<String, Response>>>,
}

impl Server {
    pub fn new() -> Self {
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

    pub fn route(&self, path: &str, response: Response) {
        self.routes
            .lock()
            .expect("the routes")
            .insert(path.to_owned(), response);
    }

    pub fn requests(&self) -> Vec<String> {
        self.requests.lock().expect("the requests").clone()
    }
}

pub fn read_head(stream: &mut impl Read) -> String {
    let mut head = Vec::new();
    let mut byte = [0; 1];
    while !head.ends_with(b"\r\n\r\n") && stream.read(&mut byte).is_ok_and(|n| n == 1) {
        head.push(byte[0]);
    }
    String::from_utf8_lossy(&head).into_owned()
}

pub fn fixture(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    fs::read(path).expect("the fixture is read")
}

/// A zip archive holding these entries.
pub fn archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    for (name, content) in entries {
        zip.start_file(*name, SimpleFileOptions::default())
            .expect("an entry");
        zip.write_all(content).expect("its content");
    }
    zip.finish().expect("the archive").into_inner()
}

pub fn crates_io_archive() -> Vec<u8> {
    archive(&[("RUSTSEC-2020-0071.json", &fixture("RUSTSEC-2020-0071.json"))])
}

pub fn npm_archive() -> Vec<u8> {
    archive(&[(
        "GHSA-35jh-r3h4-6jhm.json",
        &fixture("GHSA-35jh-r3h4-6jhm.json"),
    )])
}

pub fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
}

pub fn archives(cache: &Path, server: &Server, refresh: Refresh) -> Archives {
    Archives {
        cache: cache.to_path_buf(),
        base_url: server.base.clone(),
        refresh,
        lock_wait: Duration::from_secs(60),
    }
}

pub fn ids(snapshot: &Snapshot) -> Vec<&str> {
    snapshot
        .vulnerabilities
        .iter()
        .map(|v| v.id.as_str())
        .collect()
}

pub fn fetch_error(cache: &Path, server: &Server, refresh: Refresh, ecosystem: &str) -> FetchError {
    archives(cache, server, refresh)
        .fetch(&[ecosystem], || at(1_000))
        .expect_err("the fetch fails")
}
