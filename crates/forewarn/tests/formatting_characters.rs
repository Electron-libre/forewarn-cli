//! The bidirectional and invisible formatting characters of a value read from the SBOM or a feed, escaped in the human
//! reports of `forewarn check` and `forewarn match` and in the errors of standard error, driven through the binary
//! (`specs/cli-check.md` CHK-14, `specs/cli-match.md` MCH-18, MCH-23).

mod common;

use std::fs;

use common::{bom, run};
use serde_json::json;
use tempfile::TempDir;

// spec: CHK-14
#[test]
fn check_escapes_the_formatting_characters_of_a_component() {
    let input = bom(
        "1.6",
        &json!([{"type": "library", "name": "evil", "version": "1\u{202e}0\u{200b}"}]),
    );
    let run = run(&["check", "-"], Some(&input));
    assert_eq!(run.code, 1, "{}", run.stderr);
    assert_eq!(
        run.stdout.lines().nth(2),
        Some("  evil 1\\u{202e}0\\u{200b}: missing supplier, license, hash")
    );
    assert!(
        !run.stdout.contains(['\u{202e}', '\u{200b}']),
        "{}",
        run.stdout
    );
}

// spec: MCH-18
#[test]
fn match_escapes_the_formatting_characters_of_a_component() {
    let osv = TempDir::new().expect("a temporary directory");
    let record = json!({
        "id": "EVIL-1",
        "affected": [{
            "package": {"ecosystem": "crates.io", "name": "time"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}],
        }],
    });
    fs::write(
        osv.path().join("evil.json"),
        serde_json::to_vec(&record).expect("the record serializes"),
    )
    .expect("the record is written");
    let input = bom(
        "1.6",
        &json!([{
            "type": "library",
            "name": "ti\u{202e}me\u{2066}",
            "version": "0.1.43",
            "purl": "pkg:cargo/time@0.1.43",
        }]),
    );
    let run = run(
        &[
            "match",
            "--no-euvd",
            "--no-kev",
            "--osv",
            osv.path().to_str().expect("UTF-8 path"),
            "-",
        ],
        Some(&input),
    );
    assert_eq!(run.code, 1, "{}", run.stderr);
    assert!(
        run.stdout
            .contains("  ti\\u{202e}me\\u{2066} 0.1.43 (pkg:cargo/time@0.1.43): EVIL-1"),
        "{}",
        run.stdout
    );
    assert!(
        !run.stdout.contains(['\u{202e}', '\u{2066}']),
        "{}",
        run.stdout
    );
}

// spec: MCH-23
#[test]
fn an_error_escapes_the_formatting_characters_of_a_file_name() {
    let osv = TempDir::new().expect("a temporary directory");
    fs::write(osv.path().join("a\u{202e}b\u{feff}.json"), "not json").expect("the file is written");
    let input = bom("1.6", &json!([]));
    let run = run(
        &[
            "match",
            "--no-euvd",
            "--no-kev",
            "--osv",
            osv.path().to_str().expect("UTF-8 path"),
            "-",
        ],
        Some(&input),
    );
    assert_eq!(run.code, 5, "{}", run.stderr);
    assert!(
        run.stderr.contains("a\\u{202e}b\\u{feff}.json"),
        "{}",
        run.stderr
    );
    assert!(
        !run.stderr.contains(['\u{202e}', '\u{feff}']),
        "{}",
        run.stderr
    );
}
