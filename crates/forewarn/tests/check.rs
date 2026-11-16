//! The `forewarn check` command, driven through the binary (`specs/cli-check.md`).

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use common::{bom, json_report, run};
use serde_json::{Value, json};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn syft_fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../forewarn-cyclonedx/tests/fixtures/syft.cdx.json")
}

fn complete_component(name: &str) -> Value {
    json!({
        "type": "library",
        "name": name,
        "version": "1.0.0",
        "supplier": {"name": "Acme"},
        "licenses": [{"license": {"id": "MIT"}}],
        "hashes": [{"alg": "SHA-256", "content": "ab12"}],
    })
}

// spec: CHK-H1, CHK-H4, CHK-1, CHK-2, CHK-3, CHK-9, CHK-15
#[test]
fn reports_the_gaps_of_the_sbom_of_syft_and_exits_with_1() {
    let path = syft_fixture();
    let run = run(&["check", path.to_str().expect("UTF-8 path")], None);
    assert_eq!(run.code, 1, "{}", run.stderr);
    assert_eq!(run.stderr, "");
    let lines: Vec<&str> = run.stdout.lines().collect();
    assert_eq!(lines[0], "SBOM: CycloneDX 1.6");
    assert_eq!(lines[1], "3 of 3 components incomplete:");
    assert_eq!(
        lines[2..],
        [
            "  itoa 1.0.19 (pkg:cargo/itoa@1.0.19): missing supplier, license, hash",
            "  rollcall-fixture-sample 0.1.0: missing supplier, license, hash",
            "  semver 1.0.28 (pkg:cargo/semver@1.0.28): missing supplier, license, hash",
            "Not checked, file components (1):",
            "  /Cargo.lock",
        ]
    );
}

// spec: CHK-H3, CHK-1, CHK-3, CHK-7
#[test]
fn flags_a_complete_sbom_below_the_bsi_minimum_and_exits_with_0() {
    let path = fixture("complete-1.5.cdx.json");
    let run = run(&["check", path.to_str().expect("UTF-8 path")], None);
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert_eq!(run.stderr, "");
    assert_eq!(
        run.stdout,
        "SBOM: CycloneDX 1.5 (below the BSI TR-03183-2 minimum, 1.6)\n\
         Complete: 2 components checked, none missing a supplier, a license or a hash\n"
    );
}

// spec: CHK-4, CHK-7
#[test]
fn reads_the_sbom_from_standard_input() {
    let input = bom("1.6", &json!([complete_component("serde")]));
    let run = run(&["check", "-"], Some(&input));
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert_eq!(
        run.stdout,
        "SBOM: CycloneDX 1.6\nComplete: 1 component checked, none missing a supplier, a license or a hash\n"
    );
}

// spec: CHK-2
#[test]
fn shows_the_name_alone_of_a_component_with_no_version_nor_purl() {
    let input = bom("1.7", &json!([{"type": "library", "name": "bare"}]));
    let run = run(&["check", "-"], Some(&input));
    assert_eq!(run.code, 1, "{}", run.stderr);
    assert!(
        run.stdout
            .contains("\n  bare: missing supplier, license, hash\n"),
        "{}",
        run.stdout
    );
}

// spec: SBR-5, SBC-4
#[test]
fn a_supplier_given_only_by_url_or_an_author_only_by_email_is_not_a_gap() {
    let mut by_url = complete_component("by-url");
    by_url["supplier"] = json!({"url": ["https://example.com"]});
    let mut by_email = complete_component("by-email");
    by_email.as_object_mut().expect("object").remove("supplier");
    by_email["authors"] = json!([{"email": "dev@example.com"}]);
    let input = bom("1.6", &json!([by_url, by_email]));
    let run = run(&["check", "-"], Some(&input));
    assert_eq!(run.code, 0, "{}{}", run.stdout, run.stderr);
}

// spec: CHK-3, CHK-7
#[test]
fn an_sbom_with_no_component_is_complete() {
    let run = run(&["check", "-"], Some(&bom("1.6", &json!([]))));
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert!(
        run.stdout.contains("Complete: 0 components checked"),
        "{}",
        run.stdout
    );
}

// spec: CHK-7, CHK-8
#[test]
fn a_missing_file_is_named_on_stderr_and_exits_with_3() {
    let path = fixture("does-not-exist.json");
    let path = path.to_str().expect("UTF-8 path");
    let run = run(&["check", path], None);
    assert_eq!(run.code, 3);
    assert_eq!(run.stdout, "");
    assert_eq!(run.stderr.lines().count(), 1, "{}", run.stderr);
    assert!(run.stderr.contains(path), "{}", run.stderr);
    assert!(
        run.stderr.contains("cannot read the input"),
        "{}",
        run.stderr
    );
}

// spec: CHK-7, CHK-8
#[test]
fn a_refused_sbom_on_standard_input_names_it_and_exits_with_3() {
    let run = run(&["check", "-"], Some(&bom("1.2", &json!([]))));
    assert_eq!(run.code, 3);
    assert_eq!(run.stdout, "");
    assert_eq!(run.stderr.lines().count(), 1, "{}", run.stderr);
    assert!(run.stderr.contains("standard input"), "{}", run.stderr);
    assert!(
        run.stderr.contains("unsupported spec version"),
        "{}",
        run.stderr
    );
}

// spec: CHK-7, CHK-11
#[test]
fn accepts_the_human_format_and_refuses_an_unknown_one() {
    let input = bom("1.6", &json!([]));
    assert_eq!(
        run(&["check", "--format", "human", "-"], Some(&input)).code,
        0
    );
    let refused = run(&["check", "--format", "xml", "-"], Some(&input));
    assert_eq!(refused.code, 2);
    assert_eq!(refused.stdout, "");
}

// spec: CHK-7
#[test]
fn a_check_with_no_sbom_is_a_usage_error() {
    assert_eq!(run(&["check"], None).code, 2);
}

// spec: CHK-12
#[test]
fn no_subcommand_prints_the_usage_and_exits_with_2() {
    let run = run(&[], None);
    assert_eq!(run.code, 2);
    assert!(run.stderr.contains("check"), "{}", run.stderr);
}

// spec: CHK-5, CHK-10, CHK-11, CHK-15
#[test]
fn prints_the_report_of_the_sbom_of_syft_as_json() {
    let path = syft_fixture();
    let run = run(
        &[
            "check",
            "--format",
            "json",
            path.to_str().expect("UTF-8 path"),
        ],
        None,
    );
    assert_eq!(run.code, 1, "{}", run.stderr);
    assert_eq!(run.stderr, "");
    let all = json!(["supplier", "license", "hash"]);
    assert_eq!(
        json_report(&run),
        json!({
            "specVersion": "1.6",
            "belowBsiMinimum": false,
            "componentCount": 3,
            "complete": false,
            "incomplete": [
                {"name": "itoa", "version": "1.0.19", "purl": "pkg:cargo/itoa@1.0.19", "missing": all},
                {"name": "rollcall-fixture-sample", "version": "0.1.0", "purl": null, "missing": all},
                {"name": "semver", "version": "1.0.28", "purl": "pkg:cargo/semver@1.0.28", "missing": all},
            ],
            "notChecked": [
                {"name": "/Cargo.lock", "version": null, "purl": null, "reason": "file"},
            ],
        })
    );
}

// spec: CHK-10, CHK-15
#[test]
fn the_json_report_of_a_complete_sbom_below_the_bsi_minimum() {
    let path = fixture("complete-1.5.cdx.json");
    let run = run(
        &[
            "check",
            "--format",
            "json",
            path.to_str().expect("UTF-8 path"),
        ],
        None,
    );
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert_eq!(
        json_report(&run),
        json!({
            "specVersion": "1.5",
            "belowBsiMinimum": true,
            "componentCount": 2,
            "complete": true,
            "incomplete": [],
            "notChecked": [],
        })
    );
}

// spec: CHK-8
#[test]
fn an_unreadable_sbom_prints_no_json() {
    let run = run(&["check", "--format", "json", "-"], Some(b"not json"));
    assert_eq!(run.code, 3);
    assert_eq!(run.stdout, "");
    assert!(run.stderr.contains("standard input"), "{}", run.stderr);
}

// spec: CHK-H2, CHK-4, CHK-5, CHK-6, CHK-10
#[test]
fn a_ci_job_pipes_an_sbom_and_reads_its_gaps_without_failing() {
    let input = std::fs::read(syft_fixture()).expect("the fixture reads");
    let run = run(
        &["check", "--format", "json", "--allow-incomplete", "-"],
        Some(&input),
    );
    assert_eq!(run.code, 0, "{}", run.stderr);
    let report = json_report(&run);
    assert_eq!(report["complete"], json!(false));
    assert_eq!(report["incomplete"].as_array().map(Vec::len), Some(3));
}

// spec: CHK-6
#[test]
fn allow_incomplete_leaves_the_human_report_unchanged() {
    let path = syft_fixture();
    let path = path.to_str().expect("UTF-8 path");
    let failing = run(&["check", path], None);
    let allowed = run(&["check", "--allow-incomplete", path], None);
    assert_eq!((failing.code, allowed.code), (1, 0));
    assert_eq!(allowed.stdout, failing.stdout);
}

// spec: CHK-6, CHK-7
#[test]
fn allow_incomplete_still_fails_on_an_unreadable_sbom() {
    let run = run(&["check", "--allow-incomplete", "-"], Some(b"{}"));
    assert_eq!(run.code, 3);
}

// spec: CHK-14
#[test]
fn escapes_the_control_characters_of_a_component_in_the_human_report() {
    let input = bom(
        "1.6",
        &json!([{"type": "library", "name": "evil\n  fake: missing nothing\u{1b}[2J", "version": "1\t0"}]),
    );
    let run = run(&["check", "-"], Some(&input));
    assert_eq!(run.code, 1, "{}", run.stderr);
    assert_eq!(
        run.stdout.lines().nth(2),
        Some("  evil\\n  fake: missing nothing\\u{1b}[2J 1\\t0: missing supplier, license, hash")
    );
}

// spec: CHK-3
#[test]
fn counts_one_component_in_the_singular() {
    let input = bom("1.6", &json!([{"type": "library", "name": "bare"}]));
    let run = run(&["check", "-"], Some(&input));
    assert_eq!(
        run.stdout.lines().nth(1),
        Some("1 of 1 component incomplete:")
    );
}

// spec: CHK-7
#[cfg(unix)]
#[test]
fn a_path_that_is_not_utf8_is_read_not_refused() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let path = fixture("missing-\u{e9}.json").into_os_string();
    let mut bytes = path.as_bytes().to_vec();
    bytes.retain(|&b| b != 0xC3);
    let output = Command::new(env!("CARGO_BIN_EXE_forewarn"))
        .arg("check")
        .arg(OsStr::from_bytes(&bytes))
        .output()
        .expect("the binary runs");
    assert_eq!(output.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("cannot read the input"), "{stderr}");
}

// spec: CHK-7, CHK-13
#[cfg(target_os = "linux")]
#[test]
fn a_report_that_cannot_be_written_is_named_and_exits_with_4() {
    let full = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .expect("/dev/full opens");
    let path = fixture("complete-1.5.cdx.json");
    let output = Command::new(env!("CARGO_BIN_EXE_forewarn"))
        .arg("check")
        .arg(path)
        .stdout(full)
        .output()
        .expect("the binary runs");
    assert_eq!(output.status.code(), Some(4));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(stderr.lines().count(), 1, "{stderr}");
    assert!(stderr.contains("standard output"), "{stderr}");
}

// spec: CHK-3, CHK-7, CHK-15
#[test]
fn a_file_component_with_no_supplier_leaves_complete_packages_complete() {
    let input = bom(
        "1.6",
        &json!([
            complete_component("serde"),
            {"type": "file", "name": "/requirements.txt", "hashes": [{"alg": "SHA-1", "content": "ab"}]},
        ]),
    );
    let run = run(&["check", "-"], Some(&input));
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert_eq!(
        run.stdout,
        "SBOM: CycloneDX 1.6\n\
         Complete: 1 component checked, none missing a supplier, a license or a hash\n\
         Not checked, file components (1):\n  /requirements.txt\n"
    );
}
