//! The `forewarn match` command, driven through the binary (`specs/cli-match.md`).

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use common::{bom, json_report, run};
use serde_json::{Value, json};
use tempfile::TempDir;

/// The directory of the real OSV records the OSV adapter is tested with: `RUSTSEC-2020-0071` (`time`, alias
/// `CVE-2020-26235`), `GHSA-35jh-r3h4-6jhm` (`lodash` before 4.17.21), a withdrawn `shlex` record and a
/// `rustc-serialize` one.
fn osv_fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../forewarn-osv/tests/fixtures")
}

fn osv_fixture(name: &str) -> PathBuf {
    osv_fixtures().join(name)
}

/// The KEV catalog of the KEV adapter's tests, which names none of the CVEs of the OSV fixtures.
fn kev_fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../forewarn-exploited/tests/fixtures/kev.json")
}

fn path(path: &Path) -> &str {
    path.to_str().expect("UTF-8 path")
}

fn component(name: &str, version: &str, purl: Option<&str>) -> Value {
    let mut component = json!({"type": "library", "name": name, "version": version});
    if let Some(purl) = purl {
        component["purl"] = json!(purl);
    }
    component
}

/// `time` 0.1.43 (affected), a component without a package URL, `serde` 1.0.0 (clean).
fn three_components() -> Vec<u8> {
    bom(
        "1.6",
        &json!([
            component("time", "0.1.43", Some("pkg:cargo/time@0.1.43")),
            component("bare", "1.0", None),
            component("serde", "1.0.0", Some("pkg:cargo/serde@1.0.0")),
        ]),
    )
}

/// A directory holding these OSV records, each written to `<id>.json`.
fn records(records: &[Value]) -> TempDir {
    let directory = TempDir::new().expect("a temporary directory");
    for (i, record) in records.iter().enumerate() {
        fs::write(
            directory.path().join(format!("{i}.json")),
            serde_json::to_vec(record).expect("the record serializes"),
        )
        .expect("the record is written");
    }
    directory
}

// spec: MCH-H1, MCH-1, MCH-2, MCH-3, MCH-4, MCH-6, MCH-7, MCH-10, MCH-15, MCH-22
#[test]
fn lists_the_affected_components_apart_from_those_not_evaluated_and_exits_with_1() {
    let osv = osv_fixtures();
    let kev = kev_fixture();
    let run = run(
        &[
            "match",
            "--no-euvd",
            "--osv",
            path(&osv),
            "--kev",
            path(&kev),
            "-",
        ],
        Some(&three_components()),
    );
    assert_eq!(run.code, 1, "{}", run.stderr);
    assert_eq!(run.stderr, "");
    assert_eq!(
        run.stdout,
        format!(
            "SBOM: CycloneDX 1.6, 3 components\n\
             OSV records:\n  {}: 4 records, local\n\
             Exploited lists:\n  CISA KEV: catalog 2026.11.10 released 2026-11-10, 2 entries, local {}\n\
             Affected (1, 0 actively exploited):\n  time 0.1.43 (pkg:cargo/time@0.1.43): CVE-2020-26235 \
             (GHSA-wcg3-cvx6-7396, RUSTSEC-2020-0071), records RUSTSEC-2020-0071 from RUSTSEC\n\
             Not evaluated (1):\n  bare 1.0: no package URL\n\
             Clean: 1 of 3 components\n",
            osv.display(),
            kev.display()
        )
    );
}

// spec: MCH-8, MCH-16, MCH-17
#[test]
fn prints_the_same_result_as_json() {
    let osv = osv_fixtures();
    let run = run(
        &[
            "match",
            "--no-euvd",
            "--no-kev",
            "--format",
            "json",
            "--osv",
            path(&osv),
            "-",
        ],
        Some(&three_components()),
    );
    assert_eq!(run.code, 1, "{}", run.stderr);
    assert_eq!(
        json_report(&run),
        json!({
            "specVersion": "1.6",
            "componentCount": 3,
            "cleanCount": 1,
            "osv": [{"kind": "local", "path": path(&osv), "recordCount": 4}],
            "exploitedLists": [],
            "exploitedCount": 0,
            "awareSince": null,
            "measureAvailable": null,
            "affected": [{
                "name": "time",
                "version": "0.1.43",
                "purl": "pkg:cargo/time@0.1.43",
                "id": "CVE-2020-26235",
                "aliases": ["GHSA-wcg3-cvx6-7396", "RUSTSEC-2020-0071"],
                "records": [{"id": "RUSTSEC-2020-0071", "source": "RUSTSEC", "affects": true}],
                "exploited": [],
                "deadlines": null,
            }],
            "notEvaluated": [{
                "name": "bare",
                "version": "1.0",
                "purl": null,
                "reason": "no package URL",
                "vulnerabilityId": null,
            }],
        })
    );
}

// spec: MCH-6, MCH-16
#[test]
fn reads_several_osv_paths_files_or_directories_in_order() {
    let lodash = osv_fixture("GHSA-35jh-r3h4-6jhm.json");
    let time = osv_fixture("RUSTSEC-2020-0071.json");
    let input = bom(
        "1.6",
        &json!([
            component("time", "0.1.43", Some("pkg:cargo/time@0.1.43")),
            component("lodash", "4.17.20", Some("pkg:npm/lodash@4.17.20")),
        ]),
    );
    let run = run(
        &[
            "match",
            "--no-euvd",
            "--no-kev",
            "--format",
            "json",
            "--osv",
            path(&lodash),
            "--osv",
            path(&time),
            "-",
        ],
        Some(&input),
    );
    assert_eq!(run.code, 1, "{}", run.stderr);
    let report = json_report(&run);
    assert_eq!(
        report["osv"],
        json!([
            {"kind": "local", "path": path(&lodash), "recordCount": 1},
            {"kind": "local", "path": path(&time), "recordCount": 1},
        ])
    );
    let ids: Vec<&Value> = report["affected"]
        .as_array()
        .expect("an array")
        .iter()
        .map(|m| &m["records"][0]["id"])
        .collect();
    assert_eq!(
        ids,
        [&json!("RUSTSEC-2020-0071"), &json!("GHSA-35jh-r3h4-6jhm")]
    );
}

// spec: MCH-3, MCH-9, MCH-10
#[test]
fn an_sbom_no_record_affects_is_clean_and_exits_with_0() {
    let input = bom(
        "1.6",
        &json!([component("time", "0.2.23", Some("pkg:cargo/time@0.2.23"))]),
    );
    let run = run(
        &[
            "match",
            "--no-euvd",
            "--no-kev",
            "--osv",
            path(&osv_fixtures()),
            "-",
        ],
        Some(&input),
    );
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert!(
        run.stdout.ends_with(
            "Affected (0, 0 actively exploited):\nNot evaluated (0):\nClean: 1 of 1 component\n"
        ),
        "{}",
        run.stdout
    );
}

// spec: MCH-9, MCH-10
#[test]
fn allow_affected_exits_with_0_and_leaves_the_report_unchanged() {
    let osv = osv_fixtures();
    let failing = run(
        &["match", "--no-euvd", "--no-kev", "--osv", path(&osv), "-"],
        Some(&three_components()),
    );
    let allowed = run(
        &[
            "match",
            "--no-euvd",
            "--no-kev",
            "--allow-affected",
            "--osv",
            path(&osv),
            "-",
        ],
        Some(&three_components()),
    );
    assert_eq!((failing.code, allowed.code), (1, 0));
    assert_eq!(allowed.stdout, failing.stdout);
}

// spec: MCH-2, MCH-3, MCH-16
#[test]
fn a_pair_not_evaluated_names_its_record_and_is_not_counted_clean() {
    let osv = records(&[json!({
        "id": "GHSA-1",
        "affected": [{
            "package": {"ecosystem": "NuGet", "name": "Newtonsoft.Json"},
            "ranges": [{"type": "GIT", "repo": "https://example.com/r.git", "events": [{"introduced": "def456"}]}],
        }],
    })]);
    let input = bom(
        "1.6",
        &json!([component(
            "Newtonsoft.Json",
            "2.1",
            Some("pkg:nuget/Newtonsoft.Json@2.1")
        )]),
    );
    let human = run(
        &[
            "match",
            "--no-euvd",
            "--no-kev",
            "--osv",
            path(osv.path()),
            "-",
        ],
        Some(&input),
    );
    assert_eq!(human.code, 0, "{}", human.stderr);
    assert!(
        human.stdout.contains(
            "Not evaluated (1):\n  Newtonsoft.Json 2.1 (pkg:nuget/Newtonsoft.Json@2.1): GHSA-1: range not evaluated\n\
             Clean: 0 of 1 component\n"
        ),
        "{}",
        human.stdout
    );
    let json = run(
        &[
            "match",
            "--no-euvd",
            "--no-kev",
            "--format",
            "json",
            "--osv",
            path(osv.path()),
            "-",
        ],
        Some(&input),
    );
    let report = json_report(&json);
    assert_eq!(report["cleanCount"], json!(0));
    assert_eq!(
        report["notEvaluated"],
        json!([{
            "name": "Newtonsoft.Json",
            "version": "2.1",
            "purl": "pkg:nuget/Newtonsoft.Json@2.1",
            "reason": "range not evaluated",
            "vulnerabilityId": "GHSA-1",
        }])
    );
}

// spec: VMT-23, VMT-24
#[test]
fn a_pypi_component_in_an_ecosystem_range_is_affected() {
    let osv = records(&[json!({
        "id": "PYSEC-1",
        "affected": [{
            "package": {"ecosystem": "PyPI", "name": "django"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.0"}]}],
        }],
    })]);
    let input = bom(
        "1.6",
        &json!([
            component("django", "2.1", Some("pkg:pypi/django@2.1")),
            component("django", "3.0.post1", Some("pkg:pypi/django@3.0.post1")),
        ]),
    );
    let json = run(
        &[
            "match",
            "--no-euvd",
            "--no-kev",
            "--format",
            "json",
            "--osv",
            path(osv.path()),
            "-",
        ],
        Some(&input),
    );
    assert_eq!(json.code, 1, "{}", json.stderr);
    let report = json_report(&json);
    assert_eq!(report["affected"][0]["version"], json!("2.1"));
    assert_eq!(report["affected"].as_array().map(Vec::len), Some(1));
    assert_eq!(report["notEvaluated"], json!([]));
    assert_eq!(report["cleanCount"], json!(1));
}

// spec: MCH-16
#[test]
fn every_reason_has_its_json_name() {
    let osv = records(&[json!({
        "id": "RUSTSEC-1",
        "affected": [{
            "package": {"ecosystem": "crates.io", "name": "odd"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}],
        }],
    })]);
    let input = bom(
        "1.6",
        &json!([
            component("bare", "1", None),
            component("bad", "1", Some("not a purl")),
            component("deb", "1", Some("pkg:deb/debian/curl@1")),
            {"type": "library", "name": "unversioned", "purl": "pkg:cargo/unversioned"},
            component("odd", "1.0", Some("pkg:cargo/odd@1.0")),
        ]),
    );
    let run = run(
        &[
            "match",
            "--no-euvd",
            "--no-kev",
            "--format",
            "json",
            "--osv",
            path(osv.path()),
            "-",
        ],
        Some(&input),
    );
    assert_eq!(run.code, 0, "{}", run.stderr);
    let reasons: Vec<Value> = json_report(&run)["notEvaluated"]
        .as_array()
        .expect("an array")
        .iter()
        .map(|n| json!([n["reason"], n["vulnerabilityId"]]))
        .collect();
    assert_eq!(
        reasons,
        [
            json!(["no package URL", null]),
            json!(["invalid package URL", null]),
            json!(["unknown ecosystem", null]),
            json!(["no version", null]),
            json!(["invalid version", "RUSTSEC-1"]),
        ]
    );
}

// spec: MCH-10, MCH-14
#[test]
fn an_unreadable_record_names_its_file_and_exits_with_5() {
    let osv = TempDir::new().expect("a temporary directory");
    let broken = osv.path().join("broken.json");
    fs::write(&broken, "not json").expect("the file is written");
    let run = run(
        &[
            "match",
            "--no-euvd",
            "--no-kev",
            "--osv",
            path(osv.path()),
            "-",
        ],
        Some(&three_components()),
    );
    assert_eq!(run.code, 5);
    assert_eq!(run.stdout, "");
    assert_eq!(run.stderr.lines().count(), 1, "{}", run.stderr);
    assert!(run.stderr.contains(path(&broken)), "{}", run.stderr);
    assert!(run.stderr.contains("not JSON"), "{}", run.stderr);
}

// spec: MCH-10, MCH-14
#[test]
fn an_unreadable_sbom_names_standard_input_and_exits_with_3() {
    let run = run(
        &[
            "match",
            "--no-euvd",
            "--no-kev",
            "--osv",
            path(&osv_fixtures()),
            "-",
        ],
        Some(b"not json"),
    );
    assert_eq!(run.code, 3);
    assert_eq!(run.stdout, "");
    assert_eq!(run.stderr.lines().count(), 1, "{}", run.stderr);
    assert!(run.stderr.contains("standard input"), "{}", run.stderr);
}

// spec: MCH-10
#[test]
fn an_unreadable_sbom_is_reported_before_the_osv_records() {
    let run = run(
        &[
            "match",
            "--no-euvd",
            "--no-kev",
            "--osv",
            "/does/not/exist",
            "/does/not/exist.json",
        ],
        None,
    );
    assert_eq!(run.code, 3, "{}", run.stderr);
    assert!(
        run.stderr.contains("/does/not/exist.json"),
        "{}",
        run.stderr
    );
}

// spec: MCH-10, MCH-17
#[test]
fn invalid_arguments_exit_with_2() {
    let input = three_components();
    let osv = osv_fixtures();
    for args in [
        vec![
            "match",
            "--no-euvd",
            "--no-kev",
            "--format",
            "xml",
            "--osv",
            path(&osv),
            "-",
        ],
        vec!["match", "--no-euvd", "--no-kev", "--osv", path(&osv)],
        vec!["match", "--no-euvd", "--no-kev", "--unknown", "-"],
    ] {
        let run = run(&args, Some(&input));
        assert_eq!(run.code, 2, "{args:?}: {}", run.stderr);
        assert_eq!(run.stdout, "");
    }
    assert_eq!(
        run(
            &[
                "match",
                "--no-euvd",
                "--no-kev",
                "--format",
                "human",
                "--osv",
                path(&osv),
                "-"
            ],
            Some(&input)
        )
        .code,
        1
    );
}

// spec: MCH-18
#[test]
fn escapes_the_control_characters_of_the_sbom_and_the_records() {
    let osv = records(&[json!({
        "id": "EVIL-1\u{1b}[2J",
        "aliases": ["CVE\nfake"],
        "affected": [{
            "package": {"ecosystem": "crates.io", "name": "time"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}],
        }],
    })]);
    let input = bom(
        "1.6",
        &json!([component("time", "0.1.43", Some("pkg:cargo/time@0.1.43"))]),
    );
    let run = run(
        &[
            "match",
            "--no-euvd",
            "--no-kev",
            "--osv",
            path(osv.path()),
            "-",
        ],
        Some(&input),
    );
    assert_eq!(run.code, 1, "{}", run.stderr);
    assert!(
        run.stdout.contains(
            "  time 0.1.43 (pkg:cargo/time@0.1.43): EVIL-1\\u{1b}[2J (CVE\\nfake), \
             records EVIL-1\\u{1b}[2J from EVIL\n"
        ),
        "{}",
        run.stdout
    );
}

// spec: MCH-1, MCH-16
#[test]
fn lists_a_vulnerability_held_by_two_records_once_with_both() {
    let mirror = json!({
        "id": "GHSA-wcg3-cvx6-7396",
        "aliases": ["RUSTSEC-2020-0071"],
        "affected": [{
            "package": {"ecosystem": "crates.io", "name": "time"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "0.2.23"}]}],
        }],
    });
    let rustsec: Value = serde_json::from_slice(
        &fs::read(osv_fixture("RUSTSEC-2020-0071.json")).expect("the fixture"),
    )
    .expect("the fixture is JSON");
    let osv = records(&[rustsec, mirror]);
    let input = three_components();
    let human = run(
        &[
            "match",
            "--no-euvd",
            "--no-kev",
            "--osv",
            path(osv.path()),
            "-",
        ],
        Some(&input),
    );
    assert_eq!(human.code, 1, "{}", human.stderr);
    assert!(
        human.stdout.contains(
            "Affected (1, 0 actively exploited):\n  time 0.1.43 (pkg:cargo/time@0.1.43): \
             CVE-2020-26235 (GHSA-wcg3-cvx6-7396, RUSTSEC-2020-0071), records GHSA-wcg3-cvx6-7396 from GHSA, \
             RUSTSEC-2020-0071 from RUSTSEC\n"
        ),
        "{}",
        human.stdout
    );
    let report = json_report(&run(
        &[
            "match",
            "--no-euvd",
            "--no-kev",
            "--format",
            "json",
            "--osv",
            path(osv.path()),
            "-",
        ],
        Some(&input),
    ));
    assert_eq!(
        report["affected"],
        json!([{
            "name": "time",
            "version": "0.1.43",
            "purl": "pkg:cargo/time@0.1.43",
            "id": "CVE-2020-26235",
            "aliases": ["GHSA-wcg3-cvx6-7396", "RUSTSEC-2020-0071"],
            "records": [
                {"id": "GHSA-wcg3-cvx6-7396", "source": "GHSA", "affects": true},
                {"id": "RUSTSEC-2020-0071", "source": "RUSTSEC", "affects": true},
            ],
            "exploited": [],
            "deadlines": null,
        }])
    );
}

// spec: MCH-1, MCH-16
#[test]
fn marks_the_records_that_do_not_affect_the_component_or_were_not_evaluated() {
    let mirror = |id: &str, ranges: Value| {
        json!({
            "id": id,
            "aliases": ["RUSTSEC-2020-0071"],
            "affected": [{"package": {"ecosystem": "crates.io", "name": "time"}, "ranges": ranges}],
        })
    };
    let fixed = mirror(
        "GHSA-fixed",
        json!([{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.1.40"}]}]),
    );
    let git = mirror(
        "GHSA-git",
        json!([{"type": "GIT", "repo": "https://example.com/time", "events": [{"introduced": "abc"}]}]),
    );
    let rustsec: Value = serde_json::from_slice(
        &fs::read(osv_fixture("RUSTSEC-2020-0071.json")).expect("the fixture"),
    )
    .expect("the fixture is JSON");
    let osv = records(&[rustsec, fixed, git]);
    let input = three_components();
    let human = run(
        &[
            "match",
            "--no-euvd",
            "--no-kev",
            "--osv",
            path(osv.path()),
            "-",
        ],
        Some(&input),
    );
    assert!(
        human.stdout.contains(
            "records GHSA-fixed from GHSA (does not affect), GHSA-git from GHSA (not evaluated), \
             RUSTSEC-2020-0071 from RUSTSEC\n"
        ),
        "{}",
        human.stdout
    );
    let report = json_report(&run(
        &[
            "match",
            "--no-euvd",
            "--no-kev",
            "--format",
            "json",
            "--osv",
            path(osv.path()),
            "-",
        ],
        Some(&input),
    ));
    assert_eq!(
        report["affected"][0]["records"],
        json!([
            {"id": "GHSA-fixed", "source": "GHSA", "affects": false},
            {"id": "GHSA-git", "source": "GHSA", "affects": null},
            {"id": "RUSTSEC-2020-0071", "source": "RUSTSEC", "affects": true},
        ])
    );
}

// spec: MCH-19
#[test]
fn the_usage_names_match_beside_check() {
    let run = run(&[], None);
    assert_eq!(run.code, 2);
    assert!(run.stderr.contains("check"), "{}", run.stderr);
    assert!(run.stderr.contains("match"), "{}", run.stderr);
}

// spec: MCH-10, MCH-20
#[cfg(target_os = "linux")]
#[test]
fn a_report_that_cannot_be_written_is_named_and_exits_with_4() {
    let full = fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .expect("/dev/full opens");
    let sbom = TempDir::new().expect("a temporary directory");
    let sbom = sbom.path().join("sbom.json");
    fs::write(&sbom, three_components()).expect("the SBOM is written");
    let output = Command::new(env!("CARGO_BIN_EXE_forewarn"))
        .args([
            "match",
            "--no-euvd",
            "--no-kev",
            "--osv",
            path(&osv_fixtures()),
            path(&sbom),
        ])
        .stdout(full)
        .output()
        .expect("the binary runs");
    assert_eq!(output.status.code(), Some(4));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(stderr.lines().count(), 1, "{stderr}");
    assert!(stderr.contains("standard output"), "{stderr}");
}

// spec: MCH-21
#[test]
fn a_record_read_twice_is_matched_once() {
    let osv = osv_fixtures();
    let time = osv_fixture("RUSTSEC-2020-0071.json");
    let run = run(
        &[
            "match",
            "--no-euvd",
            "--no-kev",
            "--format",
            "json",
            "--osv",
            path(&osv),
            "--osv",
            path(&time),
            "-",
        ],
        Some(&three_components()),
    );
    assert_eq!(run.code, 1, "{}", run.stderr);
    let report = json_report(&run);
    assert_eq!(report["affected"].as_array().map(Vec::len), Some(1));
    assert_eq!(report["osv"][1]["recordCount"], json!(1));
}

// spec: MCH-22
#[test]
fn a_directory_whose_records_are_in_subdirectories_shows_0_records() {
    let osv = TempDir::new().expect("a temporary directory");
    fs::create_dir(osv.path().join("crates.io")).expect("a subdirectory");
    fs::copy(
        osv_fixture("RUSTSEC-2020-0071.json"),
        osv.path().join("crates.io/RUSTSEC-2020-0071.json"),
    )
    .expect("the record is copied");
    let run = run(
        &[
            "match",
            "--no-euvd",
            "--no-kev",
            "--osv",
            path(osv.path()),
            "-",
        ],
        Some(&three_components()),
    );
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert!(
        run.stdout
            .contains(&format!("  {}: 0 records, local\n", osv.path().display())),
        "{}",
        run.stdout
    );
}

// spec: MCH-14, MCH-23
#[cfg(unix)]
#[test]
fn an_error_naming_a_file_with_a_newline_stays_on_one_line() {
    let osv = TempDir::new().expect("a temporary directory");
    fs::write(osv.path().join("a\n\u{1b}[2Jb.json"), "not json").expect("the file is written");
    let run = run(
        &[
            "match",
            "--no-euvd",
            "--no-kev",
            "--osv",
            path(osv.path()),
            "-",
        ],
        Some(&three_components()),
    );
    assert_eq!(run.code, 5);
    assert_eq!(run.stderr.lines().count(), 1, "{}", run.stderr);
    assert!(
        run.stderr.contains("a\\n\\u{1b}[2Jb.json"),
        "{}",
        run.stderr
    );
}
