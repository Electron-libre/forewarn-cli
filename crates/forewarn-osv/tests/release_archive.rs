//! Fetching an ecosystem `<parent>:<release>` whose archive OSV does not publish (`Debian:14`) from the archive of
//! `<parent>` (`specs/osv-fetching.md`, OSF-22 to OSF-25), against a loopback HTTP server: no test needs the network.

mod common;

use std::time::Duration;

use common::{
    Response, Server, archive, archives, at, crates_io_archive, fetch_error, fixture, ids, ok,
};
use forewarn_osv::fetch::{FetchCause, Refresh};
use tempfile::TempDir;

/// The archive of `Debian`, holding the advisory of `openssh` under `Debian:12`, `Debian:13` and `Debian:14`.
fn debian_archive() -> Vec<u8> {
    archive(&[(
        "DEBIAN-CVE-2024-6387.json",
        &fixture("DEBIAN-CVE-2024-6387.json"),
    )])
}

/// A server publishing the `Debian` and `crates.io` archives, and none of a release (404).
fn server() -> Server {
    let server = Server::new();
    server.route("/Debian/all.zip", ok(debian_archive()));
    server.route("/crates.io/all.zip", ok(crates_io_archive()));
    server
}

// spec: OSF-H4, OSF-22, OSF-14
#[test]
fn a_release_without_an_archive_is_read_from_the_archive_of_its_parent() {
    let cache = TempDir::new().expect("a cache");
    let server = server();

    let snapshots = archives(cache.path(), &server, Refresh::IfMissing)
        .fetch(&["Debian:14", "crates.io"], || at(1_000))
        .expect("the archives are fetched");

    assert_eq!(
        server.requests(),
        [
            "GET /Debian%3A14/all.zip",
            "GET /Debian/all.zip",
            "GET /crates.io/all.zip"
        ]
    );
    let [debian, crates_io] = snapshots.as_slice() else {
        panic!("two snapshots: {snapshots:?}")
    };
    assert_eq!(debian.ecosystem, "Debian");
    assert_eq!(ids(debian), ["DEBIAN-CVE-2024-6387"]);
    assert_eq!(
        debian.freshness.url,
        format!("{}/Debian/all.zip", server.base)
    );
    assert_eq!(crates_io.ecosystem, "crates.io");
    assert!(cache.path().join("Debian").is_dir());
    assert!(!cache.path().join("Debian%3A14").exists());
}

// spec: OSF-22
#[test]
fn the_parent_is_fetched_and_returned_once_for_several_releases() {
    let cache = TempDir::new().expect("a cache");
    let server = server();

    let snapshots = archives(cache.path(), &server, Refresh::Always)
        .fetch(&["Debian:14", "crates.io", "Debian:15", "Debian"], || {
            at(1_000)
        })
        .expect("the archives are fetched");

    assert_eq!(
        server.requests(),
        [
            "GET /Debian%3A14/all.zip",
            "GET /Debian/all.zip",
            "GET /crates.io/all.zip",
        ]
    );
    let ecosystems: Vec<&str> = snapshots.iter().map(|s| s.ecosystem.as_str()).collect();
    assert_eq!(ecosystems, ["Debian", "crates.io"]);
}

// spec: OSF-22, OSF-9
#[test]
fn a_cached_parent_is_read_under_its_policy_after_the_release_answers_404() {
    let cache = TempDir::new().expect("a cache");
    let server = server();
    archives(cache.path(), &server, Refresh::IfMissing)
        .fetch(&["Debian"], || at(1_000))
        .expect("the parent is fetched");

    let snapshots = archives(cache.path(), &server, Refresh::IfMissing)
        .fetch(&["Debian:14"], || at(2_000))
        .expect("the release is fetched");

    assert_eq!(
        server.requests(),
        ["GET /Debian/all.zip", "GET /Debian%3A14/all.zip"]
    );
    assert_eq!(snapshots[0].ecosystem, "Debian");
    assert_eq!(snapshots[0].freshness.downloaded_at, at(1_000));
}

// spec: OSF-23
#[test]
fn offline_a_release_not_cached_is_read_from_its_cached_parent() {
    let cache = TempDir::new().expect("a cache");
    let server = server();
    archives(cache.path(), &server, Refresh::IfMissing)
        .fetch(&["Debian:14"], || at(1_000))
        .expect("the parent is fetched");
    let before = server.requests().len();

    let snapshots = archives(cache.path(), &server, Refresh::Offline)
        .fetch(&["Debian:14"], || at(2_000))
        .expect("the parent is read");

    assert_eq!(server.requests().len(), before);
    assert_eq!(snapshots[0].ecosystem, "Debian");
    assert_eq!(ids(&snapshots[0]), ["DEBIAN-CVE-2024-6387"]);
}

// spec: OSF-23
#[test]
fn offline_a_release_with_neither_snapshot_is_not_cached() {
    let cache = TempDir::new().expect("a cache");
    let server = server();

    let error = fetch_error(cache.path(), &server, Refresh::Offline, "Debian:14");

    assert_eq!(error.ecosystem, "Debian:14");
    assert_eq!(error.cause, FetchCause::NotCached);
    assert_eq!(server.requests(), Vec::<String>::new());
}

// spec: OSF-24
#[test]
fn a_parent_that_cannot_be_fetched_fails_naming_the_release() {
    let cache = TempDir::new().expect("a cache");
    let server = Server::new();

    let error = fetch_error(cache.path(), &server, Refresh::IfMissing, "Debian:14");

    assert_eq!(error.ecosystem, "Debian:14");
    let FetchCause::Download { url, .. } = &error.cause else {
        panic!("cannot download: {error:?}")
    };
    assert_eq!(url, &format!("{}/Debian/all.zip", server.base));
    assert_eq!(
        server.requests(),
        ["GET /Debian%3A14/all.zip", "GET /Debian/all.zip"]
    );
}

// spec: OSF-25
#[test]
fn an_ecosystem_without_a_release_answering_404_fails_after_one_request() {
    let cache = TempDir::new().expect("a cache");
    let server = server();

    let error = fetch_error(cache.path(), &server, Refresh::IfMissing, "npm");

    assert!(
        matches!(error.cause, FetchCause::Download { .. }),
        "{error:?}"
    );
    assert!(error.to_string().contains("404"), "{error}");
    assert_eq!(server.requests(), ["GET /npm/all.zip"]);
}

// spec: OSF-22
#[test]
fn a_release_failing_otherwise_than_404_does_not_fall_back() {
    let cache = TempDir::new().expect("a cache");
    let server = server();
    server.route(
        "/Debian%3A14/all.zip",
        Response {
            status: 503,
            headers: Vec::new(),
            body: b"unavailable".to_vec(),
            delay: Duration::ZERO,
        },
    );

    let error = fetch_error(cache.path(), &server, Refresh::IfMissing, "Debian:14");

    assert!(error.to_string().contains("503"), "{error}");
    assert_eq!(server.requests(), ["GET /Debian%3A14/all.zip"]);
}

// spec: OSF-22
#[test]
fn the_parent_stands_for_every_release_of_the_list() {
    let cache = TempDir::new().expect("a cache");
    let server = server();
    server.route("/Debian%3A13/all.zip", ok(debian_archive()));

    let snapshots = archives(cache.path(), &server, Refresh::IfMissing)
        .fetch(&["Debian:13", "Debian:14", "Debian:15"], || at(1_000))
        .expect("the archives are fetched");

    assert_eq!(
        server.requests(),
        [
            "GET /Debian%3A13/all.zip",
            "GET /Debian%3A14/all.zip",
            "GET /Debian/all.zip"
        ]
    );
    let ecosystems: Vec<&str> = snapshots.iter().map(|s| s.ecosystem.as_str()).collect();
    assert_eq!(ecosystems, ["Debian"]);
}

// spec: OSF-22
#[test]
fn a_release_after_its_parent_is_not_fetched() {
    let cache = TempDir::new().expect("a cache");
    let server = server();
    server.route("/Debian%3A13/all.zip", ok(debian_archive()));

    let snapshots = archives(cache.path(), &server, Refresh::IfMissing)
        .fetch(&["Debian:14", "Debian:13"], || at(1_000))
        .expect("the archives are fetched");

    assert_eq!(
        server.requests(),
        ["GET /Debian%3A14/all.zip", "GET /Debian/all.zip"]
    );
    assert_eq!(snapshots.len(), 1);
}

// spec: OSF-22
#[test]
fn a_parent_named_in_the_list_stands_for_its_releases_fetched_before_it() {
    let cache = TempDir::new().expect("a cache");
    let server = server();
    server.route("/Debian%3A13/all.zip", ok(debian_archive()));

    let snapshots = archives(cache.path(), &server, Refresh::IfMissing)
        .fetch(&["crates.io", "Debian:13", "Debian", "Debian:14"], || {
            at(1_000)
        })
        .expect("the archives are fetched");

    assert_eq!(
        server.requests(),
        [
            "GET /crates.io/all.zip",
            "GET /Debian%3A13/all.zip",
            "GET /Debian/all.zip"
        ]
    );
    let ecosystems: Vec<&str> = snapshots.iter().map(|s| s.ecosystem.as_str()).collect();
    assert_eq!(ecosystems, ["crates.io", "Debian"]);
}
