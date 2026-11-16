//! Reading a directory of OSV record files, laid out as an OSV ecosystem archive (`specs/osv-reading.md`).

use std::fs;
use std::path::{Path, PathBuf};

use forewarn_osv::{Cause, read_directory};
use tempfile::TempDir;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn copy_fixture(dir: &TempDir, name: &str) {
    fs::copy(fixture(name), dir.path().join(name)).expect("the fixture is copied");
}

fn ids(dir: &Path) -> Vec<String> {
    read_directory(dir)
        .expect("the directory is read")
        .into_iter()
        .map(|v| v.id)
        .collect()
}

// spec: OSR-H2, OSR-2, OSR-7
#[test]
fn a_directory_of_records_is_read_in_file_name_order_ignoring_other_files() {
    let dir = TempDir::new().expect("a temporary directory");
    copy_fixture(&dir, "RUSTSEC-2020-0071.json");
    copy_fixture(&dir, "GHSA-35jh-r3h4-6jhm.json");
    fs::write(dir.path().join("README.txt"), "not a record").expect("written");

    assert_eq!(
        ids(dir.path()),
        ["GHSA-35jh-r3h4-6jhm", "RUSTSEC-2020-0071"]
    );
}

// spec: OSR-7
#[test]
fn subdirectories_are_not_read() {
    let dir = TempDir::new().expect("a temporary directory");
    copy_fixture(&dir, "RUSTSEC-2020-0071.json");
    let nested = dir.path().join("nested.json");
    fs::create_dir(&nested).expect("created");
    fs::copy(
        fixture("GHSA-35jh-r3h4-6jhm.json"),
        nested.join("GHSA-35jh-r3h4-6jhm.json"),
    )
    .expect("copied");

    assert_eq!(ids(dir.path()), ["RUSTSEC-2020-0071"]);
}

// spec: OSR-7
#[test]
fn file_names_are_ordered_by_bytes() {
    let dir = TempDir::new().expect("a temporary directory");
    // No two names differ only by case: a case-insensitive file system (macOS) would keep one.
    for (file, id) in [("b.json", "B-1"), ("C.json", "C-1"), ("a.json", "A-1")] {
        fs::write(dir.path().join(file), format!(r#"{{"id":"{id}"}}"#)).expect("written");
    }

    assert_eq!(ids(dir.path()), ["C-1", "A-1", "B-1"]);
}

// spec: OSR-2
#[test]
fn an_empty_directory_gives_no_vulnerability() {
    let dir = TempDir::new().expect("a temporary directory");

    assert_eq!(ids(dir.path()), Vec::<String>::new());
}

// spec: OSR-3, OSR-9
#[test]
fn a_record_that_cannot_be_read_fails_the_directory_naming_the_file() {
    let dir = TempDir::new().expect("a temporary directory");
    copy_fixture(&dir, "RUSTSEC-2020-0071.json");
    let broken = dir.path().join("broken.json");
    fs::write(&broken, "{ not json").expect("written");

    let error = read_directory(dir.path()).expect_err("the directory is refused");

    assert!(matches!(error.cause, Cause::NotJson(_)), "{error}");
    assert_eq!(error.path, broken);
    let message = error.to_string();
    assert!(message.contains("broken.json"), "{message}");
    assert!(message.contains("not JSON"), "{message}");
}

// spec: OSR-36, OSR-3
#[test]
fn a_record_with_a_blank_id_fails_the_directory_naming_the_file() {
    let dir = TempDir::new().expect("a temporary directory");
    copy_fixture(&dir, "RUSTSEC-2020-0071.json");
    let blank = dir.path().join("blank.json");
    fs::write(&blank, r#"{ "id": " " }"#).expect("written");

    let error = read_directory(dir.path()).expect_err("the directory is refused");

    assert!(matches!(error.cause, Cause::Invalid(_)), "{error}");
    assert_eq!(error.path, blank);
    let message = error.to_string();
    assert!(message.contains("blank.json"), "{message}");
    assert!(message.contains("invalid OSV record"), "{message}");
}

// spec: OSR-3, OSR-9
#[test]
fn a_missing_directory_cannot_be_read_and_is_named() {
    let dir = TempDir::new().expect("a temporary directory");
    let absent = dir.path().join("absent");

    let error = read_directory(&absent).expect_err("the directory is refused");

    assert!(matches!(error.cause, Cause::Io(_)), "{error}");
    assert_eq!(error.path, absent);
    assert!(
        error.to_string().contains("cannot read the input"),
        "{error}"
    );
}

// spec: OSR-3
#[cfg(unix)]
#[test]
fn a_dangling_link_fails_the_directory_naming_it() {
    let dir = TempDir::new().expect("a temporary directory");
    copy_fixture(&dir, "RUSTSEC-2020-0071.json");
    let link = dir.path().join("GHSA-x.json");
    std::os::unix::fs::symlink(dir.path().join("absent"), &link).expect("linked");

    let error = read_directory(dir.path()).expect_err("the directory is refused");

    assert!(matches!(error.cause, Cause::Io(_)), "{error}");
    assert_eq!(error.path, link);
}
