//! How the paths a report or an error line names are printed, driven through the binary (`specs/cli-check.md`
//! CHK-16, `specs/cli-match.md` MCH-43): escaped as any value, but on Windows each backslash, the separator, as it is.

mod common;

#[cfg(windows)]
use std::fs;
use std::path::Path;

#[cfg(windows)]
use common::bom;
use common::run;
#[cfg(windows)]
use serde_json::json;
use tempfile::TempDir;

fn path(path: &Path) -> &str {
    path.to_str().expect("UTF-8 path")
}

/// An SBOM of one component, `time` 0.1.43.
#[cfg(windows)]
fn one_component() -> Vec<u8> {
    bom(
        "1.6",
        &json!([{
            "type": "library",
            "name": "time",
            "version": "0.1.43",
            "purl": "pkg:cargo/time@0.1.43"
        }]),
    )
}

// spec: CHK-16
#[cfg(unix)]
#[test]
fn a_backslash_of_a_unix_file_name_is_printed_twice() {
    let directory = TempDir::new().expect("a temporary directory");
    let missing = directory.path().join("a\\b.json");
    let run = run(&["check", path(&missing)], None);
    assert_eq!(run.code, 3, "{}", run.stdout);
    assert!(
        run.stderr.starts_with(&format!(
            "error: {}/a\\\\b.json: cannot read the input",
            directory.path().display()
        )),
        "{}",
        run.stderr
    );
}

// spec: CHK-16
#[cfg(windows)]
#[test]
fn a_windows_path_that_cannot_be_read_is_named_as_written() {
    let directory = TempDir::new().expect("a temporary directory");
    let missing = directory.path().join("shop.json");
    let run = run(&["check", path(&missing)], None);
    assert_eq!(run.code, 3, "{}", run.stdout);
    assert!(
        run.stderr.starts_with(&format!(
            "error: {}: cannot read the input",
            missing.display()
        )),
        "{}",
        run.stderr
    );
    assert!(!run.stderr.contains("\\\\"), "{}", run.stderr);
}

// spec: MCH-43
#[cfg(windows)]
#[test]
fn the_osv_and_vex_paths_of_a_windows_report_read_as_written() {
    let directory = TempDir::new().expect("a temporary directory");
    let osv = directory.path().join("osv");
    fs::create_dir(&osv).expect("the directory is created");
    let vex = directory.path().join("vex.json");
    fs::write(
        &vex,
        serde_json::to_vec(&json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "vulnerabilities": []
        }))
        .expect("the document serializes"),
    )
    .expect("the document is written");
    let run = run(
        &[
            "match",
            "--no-euvd",
            "--no-kev",
            "--osv",
            path(&osv),
            "--vex",
            path(&vex),
            "-",
        ],
        Some(&one_component()),
    );
    assert_eq!(run.code, 0, "{}", run.stderr);
    for printed in [osv.display().to_string(), vex.display().to_string()] {
        assert!(run.stdout.contains(&printed), "{printed}: {}", run.stdout);
    }
    assert!(!run.stdout.contains("\\\\"), "{}", run.stdout);
}

// spec: MCH-43
#[cfg(windows)]
#[test]
fn a_windows_error_keeps_its_separators_and_escapes_a_hidden_character() {
    let osv = TempDir::new().expect("a temporary directory");
    fs::write(osv.path().join("a\u{202e}b.json"), "not json").expect("the file is written");
    let run = run(
        &[
            "match",
            "--no-euvd",
            "--no-kev",
            "--osv",
            path(osv.path()),
            "-",
        ],
        Some(&one_component()),
    );
    assert_eq!(run.code, 5, "{}", run.stdout);
    assert!(
        run.stderr.starts_with(&format!(
            "error: {}\\a\\u{{202e}}b.json: not JSON",
            osv.path().display()
        )),
        "{}",
        run.stderr
    );
}
