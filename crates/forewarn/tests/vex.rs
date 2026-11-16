//! `forewarn match` applying the VEX verdicts of the SBOM and of `--vex` files, driven through the binary
//! (`specs/cli-match-vex.md`).

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use common::{json_report, run};
use serde_json::{Value, json};
use tempfile::TempDir;

/// The real OSV records of the OSV adapter's tests: `RUSTSEC-2020-0071` affects `time` 0.1.43 (`CVE-2020-26235`).
fn osv_fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../forewarn-osv/tests/fixtures")
}

/// The KEV catalog of the KEV adapter's tests, naming `CVE-2021-44228` added on 2021-12-10.
fn kev_fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../forewarn-exploited/tests/fixtures/kev.json")
}

fn path(path: &Path) -> &str {
    path.to_str().expect("UTF-8 path")
}

/// A directory holding an OSV record of `Log4Shell`, `CVE-2021-44228`, affecting `log4j-core` before 2.15.0.
fn log4j_records() -> TempDir {
    let directory = TempDir::new().expect("a temporary directory");
    let record = json!({
        "id": "GHSA-jfh8-c2jp-5v3q",
        "modified": "2021-12-10T00:00:00Z",
        "aliases": ["CVE-2021-44228"],
        "affected": [{
            "package": {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.0-beta9"}, {"fixed": "2.15.0"}]}],
        }],
    });
    fs::write(
        directory.path().join("GHSA-jfh8-c2jp-5v3q.json"),
        serde_json::to_vec(&record).expect("the record serializes"),
    )
    .expect("the record is written");
    directory
}

fn log4j(version: &str, bom_ref: &str) -> Value {
    json!({
        "type": "library",
        "bom-ref": bom_ref,
        "name": "log4j-core",
        "version": version,
        "purl": format!("pkg:maven/org.apache.logging.log4j/log4j-core@{version}"),
    })
}

fn time() -> Value {
    json!({"type": "library", "bom-ref": "time", "name": "time", "version": "0.1.43", "purl": "pkg:cargo/time@0.1.43"})
}

fn vulnerability(id: &str, target: &str, analysis: &Value) -> Value {
    json!({"id": id, "analysis": analysis, "affects": [{"ref": target}]})
}

fn document(components: &Value, vulnerabilities: &Value) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": components,
        "vulnerabilities": vulnerabilities,
    }))
    .expect("the document serializes")
}

/// A work directory holding the `Log4Shell` record and each named document.
struct Work {
    records: TempDir,
    directory: TempDir,
}

impl Work {
    fn new(documents: &[(&str, Vec<u8>)]) -> Self {
        let directory = TempDir::new().expect("a temporary directory");
        for (name, bytes) in documents {
            fs::write(directory.path().join(name), bytes).expect("the document is written");
        }
        Self {
            records: log4j_records(),
            directory,
        }
    }

    fn file(&self, name: &str) -> PathBuf {
        self.directory.path().join(name)
    }

    /// Runs `forewarn match` on `sbom` against the OSV fixtures, the `Log4Shell` record and the KEV fixture, with
    /// `extra`.
    fn run(&self, extra: &[&str], sbom: &[u8]) -> common::Run {
        let osv = osv_fixtures();
        let kev = kev_fixture();
        let mut args = vec![
            "match",
            "--no-euvd",
            "--kev",
            path(&kev),
            "--osv",
            path(&osv),
            "--osv",
            path(self.records.path()),
        ];
        args.extend(extra);
        args.push("-");
        run(&args, Some(sbom))
    }
}

fn not_affected() -> Value {
    json!({"state": "not_affected", "justification": "code_not_reachable", "detail": "JndiLookup is removed."})
}

// spec: MVX-H1, MVX-1, MVX-3, MVX-4, MVX-5
#[test]
fn reports_apart_the_match_the_sbom_says_not_affected_with_no_draft_and_exits_with_0() {
    let work = Work::new(&[]);
    let drafts = work.file("drafts");
    let sbom = document(
        &json!([log4j("2.14.1", "log4j")]),
        &json!([vulnerability("CVE-2021-44228", "log4j", &not_affected())]),
    );
    let run = work.run(&["--drafts", path(&drafts)], &sbom);
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert!(
        run.stdout.contains(
            "VEX verdicts:\n  the SBOM: 1 verdict\nAffected (0, 0 actively exploited):\n\
             Draft early warnings (0):\n\
             Set aside by a VEX verdict (1):\n  log4j-core 2.14.1 (pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1): \
             CVE-2021-44228 (GHSA-jfh8-c2jp-5v3q)\n\
             \x20   not_affected, code_not_reachable: JndiLookup is removed. (the SBOM)\n\
             \x20   actively exploited: CISA KEV CVE-2021-44228 added 2021-12-10\n\
             Not evaluated (0):\n"
        ),
        "{}",
        run.stdout
    );
    assert!(
        !run.stdout.contains("Aware since"),
        "no deadline: {}",
        run.stdout
    );
    assert!(!drafts.exists(), "no draft is written");
}

// spec: MVX-3
#[test]
fn prints_no_vex_line_without_a_verdict_nor_vex() {
    let work = Work::new(&[]);
    let sbom = document(&json!([time()]), &json!([]));
    let run = work.run(&[], &sbom);
    assert_eq!(run.code, 1, "{}", run.stderr);
    assert!(!run.stdout.contains("VEX"), "{}", run.stdout);
    assert!(!run.stdout.contains("Set aside"), "{}", run.stdout);
}

// spec: MVX-H2, MVX-2, MVX-8
#[test]
fn applies_a_vex_file_and_lists_the_match_set_aside_in_json() {
    let vex = document(
        &json!([]),
        &json!([vulnerability(
            "CVE-2021-44228",
            "log4j",
            &json!({"state": "false_positive"})
        )]),
    );
    let work = Work::new(&[("vex.json", vex)]);
    let vex_path = work.file("vex.json");
    let sbom = document(&json!([log4j("2.14.1", "log4j"), time()]), &json!([]));
    let run = work.run(&["--format", "json", "--vex", path(&vex_path)], &sbom);
    assert_eq!(run.code, 1, "{}", run.stderr);
    let report = json_report(&run);
    assert_eq!(
        report["vex"],
        json!([
            {"kind": "sbom", "verdictCount": 0},
            {"kind": "file", "path": path(&vex_path), "verdictCount": 1},
        ])
    );
    assert_eq!(report["setAsideCount"], 1);
    assert_eq!(report["exploitedCount"], 0);
    assert_eq!(
        report["setAside"],
        json!([{
            "name": "log4j-core",
            "version": "2.14.1",
            "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
            "id": "CVE-2021-44228",
            "aliases": ["GHSA-jfh8-c2jp-5v3q"],
            "records": [{"id": "GHSA-jfh8-c2jp-5v3q", "source": "GHSA", "affects": true}],
            "exploited": [{"list": "CISA KEV", "cve": "CVE-2021-44228", "dateAdded": "2021-12-10"}],
            "verdict": {
                "state": "false_positive",
                "justification": null,
                "detail": null,
                "source": path(&vex_path),
            },
        }])
    );
    let affected: Vec<&str> = report["affected"]
        .as_array()
        .expect("an array")
        .iter()
        .map(|found| found["name"].as_str().expect("a name"))
        .collect();
    assert_eq!(affected, ["time"]);
    assert_eq!(report["unusedVerdicts"], json!([]));
}

// spec: MVX-8
#[test]
fn the_json_report_has_the_vex_members_with_no_verdict() {
    let work = Work::new(&[]);
    let sbom = document(&json!([time()]), &json!([]));
    let report = json_report(&work.run(&["--format", "json"], &sbom));
    assert_eq!(report["vex"], json!([{"kind": "sbom", "verdictCount": 0}]));
    assert_eq!(report["setAsideCount"], 0);
    assert_eq!(report["setAside"], json!([]));
    assert_eq!(report["unusedVerdicts"], json!([]));
}

// spec: MVX-4, MVX-10
#[test]
fn drafts_a_cve_with_the_components_left_and_exits_with_6() {
    let work = Work::new(&[]);
    let drafts = work.file("drafts");
    let sbom = document(
        &json!([log4j("2.14.1", "a"), log4j("2.14.0", "b")]),
        &json!([vulnerability("CVE-2021-44228", "a", &not_affected())]),
    );
    let run = work.run(&["--drafts", path(&drafts)], &sbom);
    assert_eq!(run.code, 6, "{}", run.stderr);
    assert!(
        run.stdout.contains("Affected (1, 1 actively exploited):"),
        "{}",
        run.stdout
    );
    let files: Vec<PathBuf> = fs::read_dir(&drafts)
        .expect("the drafts directory")
        .map(|entry| entry.expect("an entry").path())
        .collect();
    assert_eq!(files.len(), 1, "{files:?}");
    let draft = fs::read_to_string(&files[0]).expect("the draft");
    assert!(draft.contains("2\\.14\\.0"), "{draft}");
    assert!(!draft.contains("2\\.14\\.1"), "{draft}");
}

// spec: MVX-2
#[test]
fn keeps_a_match_a_later_vex_file_says_exploitable() {
    let say = |state: &str| {
        document(
            &json!([]),
            &json!([vulnerability(
                "CVE-2021-44228",
                "log4j",
                &json!({"state": state})
            )]),
        )
    };
    let work = Work::new(&[
        ("a.json", say("not_affected")),
        ("b.json", say("exploitable")),
    ]);
    let (a, b) = (work.file("a.json"), work.file("b.json"));
    let sbom = document(&json!([log4j("2.14.1", "log4j")]), &json!([]));
    let run = work.run(&["--vex", path(&a), "--vex", path(&b)], &sbom);
    assert_eq!(run.code, 6, "{}", run.stderr);
    assert!(
        run.stdout.contains(&format!(
            "VEX verdicts:\n  the SBOM: 0 verdicts\n  {}: 1 verdict\n  {}: 1 verdict\n",
            a.display(),
            b.display()
        )),
        "{}",
        run.stdout
    );
    assert!(
        run.stdout.contains("Set aside by a VEX verdict (0):\n"),
        "{}",
        run.stdout
    );
}

// spec: MVX-6, MVX-8
#[test]
fn lists_the_verdicts_that_name_no_match() {
    let work = Work::new(&[]);
    let sbom = document(
        &json!([log4j("2.14.1", "log4j")]),
        &json!([
            vulnerability("CVE-2021-44228", "log4j", &json!({"state": "exploitable"})),
            vulnerability("CVE-2021-44228", "lgo4j", &not_affected()),
        ]),
    );
    let run = work.run(&[], &sbom);
    assert!(
        run.stdout
            .contains("Unused VEX verdicts (1):\n  CVE-2021-44228 for lgo4j (the SBOM)\n"),
        "{}",
        run.stdout
    );
    let report = json_report(&work.run(&["--format", "json"], &sbom));
    assert_eq!(
        report["unusedVerdicts"],
        json!([{"ids": ["CVE-2021-44228"], "targets": ["lgo4j"], "source": "sbom"}])
    );
}

// spec: MVX-7
#[test]
fn a_vex_file_that_cannot_be_read_exits_with_3() {
    let work = Work::new(&[("vex.json", b"{".to_vec())]);
    let vex = work.file("vex.json");
    let sbom = document(&json!([time()]), &json!([]));
    let run = work.run(&["--vex", path(&vex)], &sbom);
    assert_eq!(run.code, 3, "{}", run.stdout);
    assert_eq!(run.stdout, "");
    assert!(
        run.stderr
            .starts_with(&format!("error: {}: not JSON", vex.display())),
        "{}",
        run.stderr
    );
    let missing = work.file("missing.json");
    let run = work.run(&["--vex", path(&missing)], &sbom);
    assert_eq!(run.code, 3, "{}", run.stdout);
    assert!(
        run.stderr.contains("cannot read the input"),
        "{}",
        run.stderr
    );
}

// spec: MVX-9
#[test]
fn escapes_the_values_of_a_verdict_in_the_human_report() {
    let work = Work::new(&[]);
    let sbom = document(
        &json!([log4j("2.14.1", "log4j")]),
        &json!([
            vulnerability(
                "CVE-2021-44228",
                "log4j",
                &json!({"state": "not_affected", "justification": "code_not_reachable", "detail": "gone\u{1b}[2J"}),
            ),
            vulnerability(
                "CVE-2021-44228",
                "x\u{202e}y",
                &json!({"state": "not_affected"})
            ),
        ]),
    );
    let run = work.run(&[], &sbom);
    assert!(run.stdout.contains("gone\\u{1b}[2J"), "{}", run.stdout);
    assert!(run.stdout.contains("x\\u{202e}y"), "{}", run.stdout);
    assert!(!run.stdout.contains('\u{1b}'), "{}", run.stdout);
}
