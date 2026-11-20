//! Fetching an ecosystem `<parent>:<release>` (`Debian:13`) from the archive of `<parent>`, never from the archive of
//! the release that OSV no longer updates (`specs/osv-fetching.md`, OSF-22 to OSF-25), against a loopback HTTP server:
//! no test needs the network.

mod common;

use common::{
    Server, archive, archives, at, crates_io_archive, fetch_error, fixture, ids, npm_archive, ok,
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

/// A server publishing the `Debian` and `crates.io` archives, and a frozen archive of `Debian:13` holding another record.
fn server() -> Server {
    let server = Server::new();
    server.route("/Debian/all.zip", ok(debian_archive()));
    server.route("/Debian%3A13/all.zip", ok(npm_archive()));
    server.route("/crates.io/all.zip", ok(crates_io_archive()));
    server
}

fn ecosystems(snapshots: &[forewarn_osv::fetch::Snapshot]) -> Vec<&str> {
    snapshots.iter().map(|s| s.ecosystem.as_str()).collect()
}

// spec: OSF-H4, OSF-22, OSF-14, OSF-17, OSF-21
#[test]
fn a_release_is_read_from_the_archive_of_its_parent_never_from_its_own() {
    let cache = TempDir::new().expect("a cache");
    let server = server();

    let snapshots = archives(cache.path(), &server, Refresh::IfMissing)
        .fetch(&["Debian:13", "crates.io"], || at(1_000))
        .expect("the archives are fetched");

    assert_eq!(
        server.requests(),
        ["GET /Debian/all.zip", "GET /crates.io/all.zip"]
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
    assert!(!cache.path().join("Debian%3A13").exists());
}

// spec: OSF-22
#[test]
fn the_parent_is_fetched_and_returned_once_for_itself_and_its_releases() {
    let cache = TempDir::new().expect("a cache");
    let server = server();

    let snapshots = archives(cache.path(), &server, Refresh::Always)
        .fetch(&["Debian:13", "crates.io", "Debian:12", "Debian"], || {
            at(1_000)
        })
        .expect("the archives are fetched");

    assert_eq!(
        server.requests(),
        ["GET /Debian/all.zip", "GET /crates.io/all.zip"]
    );
    assert_eq!(ecosystems(&snapshots), ["Debian", "crates.io"]);
}

// spec: OSF-22
#[test]
fn a_release_after_its_parent_in_the_list_is_not_fetched_again() {
    let cache = TempDir::new().expect("a cache");
    let server = server();

    let snapshots = archives(cache.path(), &server, Refresh::Always)
        .fetch(&["crates.io", "Debian", "Debian:13"], || at(1_000))
        .expect("the archives are fetched");

    assert_eq!(
        server.requests(),
        ["GET /crates.io/all.zip", "GET /Debian/all.zip"]
    );
    assert_eq!(ecosystems(&snapshots), ["crates.io", "Debian"]);
}

// spec: OSF-22, OSF-9
#[test]
fn a_cached_parent_is_read_under_its_policy_without_a_request() {
    let cache = TempDir::new().expect("a cache");
    let server = server();
    archives(cache.path(), &server, Refresh::IfMissing)
        .fetch(&["Debian"], || at(1_000))
        .expect("the parent is fetched");

    let snapshots = archives(cache.path(), &server, Refresh::IfMissing)
        .fetch(&["Debian:13"], || at(2_000))
        .expect("the release is fetched");

    assert_eq!(server.requests(), ["GET /Debian/all.zip"]);
    assert_eq!(snapshots[0].ecosystem, "Debian");
    assert_eq!(snapshots[0].freshness.downloaded_at, at(1_000));
}

/// Leaves in the cache the snapshot of `Debian:13` an earlier forewarn downloaded from the frozen release archive,
/// in its directory `Debian%3A13`, holding the record of the frozen archive.
fn leave_a_release_snapshot(cache: &TempDir) {
    let frozen = Server::new();
    frozen.route("/Debian/all.zip", ok(npm_archive()));
    archives(cache.path(), &frozen, Refresh::IfMissing)
        .fetch(&["Debian"], || at(500))
        .expect("the frozen archive is fetched");
    std::fs::rename(
        cache.path().join("Debian"),
        cache.path().join("Debian%3A13"),
    )
    .expect("the snapshot is renamed");
}

// spec: OSF-23
#[test]
fn offline_a_release_is_read_from_its_cached_parent_not_from_its_own_snapshot() {
    let cache = TempDir::new().expect("a cache");
    leave_a_release_snapshot(&cache);
    let server = server();
    archives(cache.path(), &server, Refresh::IfMissing)
        .fetch(&["Debian"], || at(1_000))
        .expect("the parent is fetched");
    let before = server.requests().len();

    let snapshots = archives(cache.path(), &server, Refresh::Offline)
        .fetch(&["Debian:13"], || at(2_000))
        .expect("the parent is read");

    assert_eq!(server.requests().len(), before);
    assert_eq!(ecosystems(&snapshots), ["Debian"]);
    assert_eq!(ids(&snapshots[0]), ["DEBIAN-CVE-2024-6387"]);
}

// spec: OSF-23
#[test]
fn offline_a_release_whose_parent_is_not_cached_is_not_cached() {
    let cache = TempDir::new().expect("a cache");
    leave_a_release_snapshot(&cache);
    let server = server();

    let error = fetch_error(cache.path(), &server, Refresh::Offline, "Debian:13");

    assert_eq!(error.ecosystem, "Debian:13");
    assert_eq!(error.cause, FetchCause::NotCached);
    assert_eq!(server.requests(), Vec::<String>::new());
}

// spec: OSF-24
#[test]
fn a_parent_that_cannot_be_fetched_fails_naming_the_release_after_one_request() {
    let cache = TempDir::new().expect("a cache");
    let server = Server::new();
    server.route("/Debian%3A13/all.zip", ok(npm_archive()));

    let error = fetch_error(cache.path(), &server, Refresh::IfMissing, "Debian:13");

    assert_eq!(error.ecosystem, "Debian:13");
    let FetchCause::Download { url, .. } = &error.cause else {
        panic!("cannot download: {error:?}")
    };
    assert_eq!(url, &format!("{}/Debian/all.zip", server.base));
    assert_eq!(server.requests(), ["GET /Debian/all.zip"]);
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
