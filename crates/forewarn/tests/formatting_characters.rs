//! The characters that hide or reorder text and the backslash of a value read from the SBOM or a feed, escaped in the
//! human reports of `forewarn check` and `forewarn match` and in the errors of standard error, driven through the binary
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

// spec: CHK-14
#[test]
fn check_escapes_the_characters_that_hide_text_beyond_the_bidirectional_ones() {
    let input = bom(
        "1.6",
        &json!([{"type": "library", "name": "evil", "version": "1\u{e0041}0\u{3164}\u{fe0f}\u{ad}"}]),
    );
    let run = run(&["check", "-"], Some(&input));
    assert_eq!(run.code, 1, "{}", run.stderr);
    assert_eq!(
        run.stdout.lines().nth(2),
        Some("  evil 1\\u{e0041}0\\u{3164}\\u{fe0f}\\u{ad}: missing supplier, license, hash")
    );
}

// spec: CHK-14
#[test]
fn check_escapes_the_backslash_so_that_a_literal_escape_differs_from_a_real_one() {
    let input = bom(
        "1.6",
        &json!([
            {"type": "library", "name": "a\\u{202e}", "version": "1"},
            {"type": "library", "name": "a\u{202e}", "version": "1"},
        ]),
    );
    let run = run(&["check", "-"], Some(&input));
    assert_eq!(run.code, 1, "{}", run.stderr);
    assert!(
        run.stdout
            .contains("  a\\\\u{202e} 1: missing supplier, license, hash"),
        "{}",
        run.stdout
    );
    assert!(
        run.stdout
            .contains("  a\\u{202e} 1: missing supplier, license, hash"),
        "{}",
        run.stdout
    );
}

// spec: MCH-18
#[test]
fn match_escapes_the_backslash_of_a_component_and_of_a_record() {
    let osv = TempDir::new().expect("a temporary directory");
    let record = json!({
        "id": "EVIL\\n-1",
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
            "name": "ti\\me",
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
            .contains("  ti\\\\me 0.1.43 (pkg:cargo/time@0.1.43): EVIL\\\\n-1"),
        "{}",
        run.stdout
    );
}

// spec: MCH-23
#[test]
fn an_error_escapes_the_backslash_of_a_file_name() {
    let osv = TempDir::new().expect("a temporary directory");
    fs::write(osv.path().join("a\\nb.json"), "not json").expect("the file is written");
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
    assert!(run.stderr.contains("a\\\\nb.json"), "{}", run.stderr);
}

// spec: MCH-23
#[test]
fn an_error_escapes_a_value_of_the_sbom_once() {
    let input = bom("1.6\u{202e}", &json!([]));
    let run = run(
        &["match", "--no-euvd", "--no-kev", "--osv", ".", "-"],
        Some(&input),
    );
    assert_ne!(run.code, 0, "{}", run.stderr);
    assert!(run.stderr.contains("\"1.6\\u{202e}\""), "{}", run.stderr);
}
