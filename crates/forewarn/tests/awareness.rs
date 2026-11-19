//! `forewarn match --awareness <file>` remembering the moment of awareness of each actively exploited CVE across runs,
//! driven through the binary (`specs/cli-match-awareness.md`).

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use common::{Run, json_report, run, run_in};
use serde_json::{Value, json};
use tempfile::TempDir;

/// The KEV catalog of the KEV adapter's tests, naming `CVE-2021-44228` and `CVE-2023-4966`.
fn kev_fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../forewarn-exploited/tests/fixtures/kev.json")
}

fn path(path: &Path) -> &str {
    path.to_str().expect("UTF-8 path")
}

const LOG4J: &str = "CVE-2021-44228";
const GATEWAY: &str = "CVE-2023-4966";

/// A work directory holding an OSV record of `CVE-2021-44228`, affecting `log4j-core` before 2.15.0, one of
/// `CVE-2023-4966`, affecting `com.example:gateway` before 2.0.0, both named by the KEV fixture, and one of
/// `CVE-2020-0001`, which it does not name, affecting `com.example:widget` before 2.0.0.
struct Work {
    directory: TempDir,
}

impl Work {
    fn new() -> Self {
        let directory = TempDir::new().expect("a temporary directory");
        let records = directory.path().join("records");
        fs::create_dir(&records).expect("the records directory is created");
        for (id, cve, package, range) in [
            (
                "GHSA-jfh8-c2jp-5v3q",
                LOG4J,
                "org.apache.logging.log4j:log4j-core",
                json!([{"introduced": "2.0-beta9"}, {"fixed": "2.15.0"}]),
            ),
            (
                "GHSA-citrix-bleed",
                GATEWAY,
                "com.example:gateway",
                json!([{"introduced": "0"}, {"fixed": "2.0.0"}]),
            ),
            (
                "GHSA-widget",
                "CVE-2020-0001",
                "com.example:widget",
                json!([{"introduced": "0"}, {"fixed": "2.0.0"}]),
            ),
        ] {
            let record = json!({
                "id": id,
                "modified": "2023-10-10T00:00:00Z",
                "aliases": [cve],
                "affected": [{
                    "package": {"ecosystem": "Maven", "name": package},
                    "ranges": [{"type": "ECOSYSTEM", "events": range}],
                }],
            });
            fs::write(
                records.join(format!("{id}.json")),
                serde_json::to_vec(&record).expect("the record serializes"),
            )
            .expect("the record is written");
        }
        Self { directory }
    }

    fn file(&self, name: &str) -> PathBuf {
        self.directory.path().join(name)
    }

    /// Runs `forewarn match` of `sbom` against the records and the KEV fixture, `extra` before the SBOM.
    fn run(&self, extra: &[&str], sbom: &[u8]) -> Run {
        let records = self.file("records");
        let kev = kev_fixture();
        let mut args = vec![
            "match",
            "--osv",
            path(&records),
            "--kev",
            path(&kev),
            "--no-euvd",
        ];
        args.extend(extra);
        args.push("-");
        run(&args, Some(sbom))
    }
}

fn log4j(version: &str) -> Value {
    json!({"type": "library", "bom-ref": format!("log4j-{version}"), "name": "log4j-core", "version": version,
           "purl": format!("pkg:maven/org.apache.logging.log4j/log4j-core@{version}")})
}

fn gateway() -> Value {
    json!({"type": "library", "bom-ref": "gateway", "name": "gateway", "version": "1.0.0",
           "purl": "pkg:maven/com.example/gateway@1.0.0"})
}

/// A component affected by a CVE no exploited list names.
fn widget() -> Value {
    json!({"type": "library", "bom-ref": "widget", "name": "widget", "version": "1.0.0",
           "purl": "pkg:maven/com.example/widget@1.0.0"})
}

/// A 1.6 SBOM of the product named `product` (none when `None`) holding `components` and the VEX `vulnerabilities`.
fn sbom_with(product: Option<&str>, components: &Value, vulnerabilities: &Value) -> Vec<u8> {
    let mut bom = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": components,
        "vulnerabilities": vulnerabilities,
    });
    if let Some(product) = product {
        bom["metadata"] =
            json!({"component": {"type": "application", "name": product, "version": "2.1.0"}});
    }
    serde_json::to_vec(&bom).expect("the SBOM serializes")
}

fn sbom(product: Option<&str>, components: &Value) -> Vec<u8> {
    sbom_with(product, components, &json!([]))
}

/// The SBOM of `shop` with `log4j-core` 2.14.1.
fn shop() -> Vec<u8> {
    sbom(Some("shop"), &json!([log4j("2.14.1")]))
}

fn entry(product: Option<&str>, cve: &str, aware_since: &str) -> Value {
    json!({"product": product, "cve": cve, "awareSince": aware_since})
}

fn moments(entries: &[Value]) -> Value {
    json!({ "awareness": entries })
}

fn read(file: &Path) -> Value {
    serde_json::from_slice(&fs::read(file).expect("the file of moments is read"))
        .expect("the file of moments is JSON")
}

fn write(file: &Path, content: &Value) {
    fs::write(
        file,
        serde_json::to_vec_pretty(content).expect("the moments serialize"),
    )
    .expect("the file of moments is written");
}

/// The member `field` of the entry of `affected` naming the component `name`.
fn affected(report: &Value, name: &str, field: &str) -> Value {
    report["affected"]
        .as_array()
        .expect("an array")
        .iter()
        .find(|found| found["name"] == name)
        .unwrap_or_else(|| panic!("{name} is affected: {report}"))[field]
        .clone()
}

// spec: AWR-H1, AWR-1, AWR-2, AWR-4, AWR-7, AWR-8
#[test]
fn a_daily_job_counts_the_deadlines_from_the_first_run_that_flagged_the_cve() {
    let work = Work::new();
    let file = work.file("state/awareness.json");
    let first = work.run(
        &[
            "--awareness",
            path(&file),
            "--aware-since",
            "2026-11-13T09:30:00Z",
            "--now",
            "2026-11-13T09:30:00Z",
        ],
        &shop(),
    );
    assert_eq!(first.code, 6, "{}", first.stderr);
    assert_eq!(
        read(&file),
        moments(&[entry(Some("shop"), LOG4J, "2026-11-13T09:30:00Z")])
    );
    assert!(
        first.stdout.contains(
            "    aware since 2026-11-13T09:30:00Z (--aware-since)\n    report by: early warning \
             2026-11-14T09:30:00Z (1d 0h 0m 0s left)"
        ),
        "{}",
        first.stdout
    );
    let written = fs::read(&file).expect("the file is read");

    let next = work.run(
        &["--awareness", path(&file), "--now", "2026-11-14T09:30:01Z"],
        &shop(),
    );
    assert_eq!(next.code, 6, "{}", next.stderr);
    assert_eq!(
        fs::read(&file).expect("the file is read"),
        written,
        "untouched"
    );
    assert!(
        next.stdout.contains(&format!(
            "    aware since 2026-11-13T09:30:00Z (from {})\n    report by: early warning \
             2026-11-14T09:30:00Z (overdue by 1s)",
            path(&file)
        )),
        "{}",
        next.stdout
    );
}

// spec: AWR-H2, AWR-1, AWR-2, AWR-5, AWR-7, AWR-12, MCH-16
#[test]
fn a_cve_flagged_later_counts_from_its_own_moment_in_the_reports_and_the_drafts() {
    let work = Work::new();
    let file = work.file("awareness.json");
    write(
        &file,
        &moments(&[entry(Some("shop"), LOG4J, "2026-11-13T09:30:00Z")]),
    );
    let drafts = work.file("drafts");
    let run = work.run(
        &[
            "--awareness",
            path(&file),
            "--aware-since",
            "2026-11-16T08:00:00Z",
            "--drafts",
            path(&drafts),
            "--format",
            "json",
        ],
        &sbom(Some("shop"), &json!([log4j("2.14.1"), gateway()])),
    );
    assert_eq!(run.code, 6, "{}", run.stderr);
    assert_eq!(
        read(&file),
        moments(&[
            entry(Some("shop"), LOG4J, "2026-11-13T09:30:00Z"),
            entry(Some("shop"), GATEWAY, "2026-11-16T08:00:00Z"),
        ])
    );
    let report = json_report(&run);
    assert_eq!(report["awareSince"], "2026-11-16T08:00:00Z");
    assert_eq!(
        affected(&report, "log4j-core", "awareSince"),
        "2026-11-13T09:30:00Z"
    );
    assert_eq!(
        affected(&report, "log4j-core", "deadlines")["earlyWarning"],
        "2026-11-14T09:30:00Z"
    );
    assert_eq!(
        affected(&report, "gateway", "awareSince"),
        "2026-11-16T08:00:00Z"
    );
    assert_eq!(
        affected(&report, "gateway", "deadlines")["earlyWarning"],
        "2026-11-17T08:00:00Z"
    );
    let draft = |cve: &str| {
        fs::read_to_string(drafts.join(format!("shop-{cve}.md"))).expect("the draft is written")
    };
    assert!(
        draft(LOG4J).contains("2026-11-14T09:30:00Z"),
        "{}",
        draft(LOG4J)
    );
    assert!(
        draft(GATEWAY).contains("2026-11-17T08:00:00Z"),
        "{}",
        draft(GATEWAY)
    );
    assert!(!draft(LOG4J).contains("2026-11-17T08:00:00Z"));
}

// spec: AWR-2, AWR-3, AWR-4
#[test]
fn a_recorded_moment_prevails_over_aware_since_which_serves_the_new_cves() {
    let work = Work::new();
    let file = work.file("awareness.json");
    write(
        &file,
        &moments(&[entry(Some("shop"), LOG4J, "2026-11-13T09:30:00Z")]),
    );
    let run = work.run(
        &[
            "--awareness",
            path(&file),
            "--aware-since",
            "2026-11-10T00:00:00Z",
            "--now",
            "2026-11-13T10:00:00Z",
        ],
        &sbom(Some("shop"), &json!([log4j("2.14.1"), gateway()])),
    );
    assert_eq!(run.code, 6, "{}", run.stderr);
    assert!(
        run.stdout.contains(&format!(
            "    aware since 2026-11-13T09:30:00Z (from {})\n    report by: early warning 2026-11-14T09:30:00Z",
            path(&file)
        )),
        "{}",
        run.stdout
    );
    assert!(
        run.stdout.contains(
            "    aware since 2026-11-10T00:00:00Z (--aware-since)\n    report by: early warning \
             2026-11-11T00:00:00Z"
        ),
        "{}",
        run.stdout
    );
    assert_eq!(
        read(&file),
        moments(&[
            entry(Some("shop"), LOG4J, "2026-11-13T09:30:00Z"),
            entry(Some("shop"), GATEWAY, "2026-11-10T00:00:00Z"),
        ])
    );
}

// spec: AWR-4
#[test]
fn says_a_moment_read_from_the_clock_is_the_moment_of_the_run() {
    let work = Work::new();
    let file = work.file("awareness.json");
    let run = work.run(&["--awareness", path(&file)], &shop());
    assert_eq!(run.code, 6, "{}", run.stderr);
    assert!(
        run.stdout
            .contains(" (the moment of the run)\n    report by: "),
        "{}",
        run.stdout
    );
}

// spec: AWR-3
#[test]
fn leaves_the_file_untouched_when_nothing_new_is_exploited() {
    let work = Work::new();
    let file = work.file("awareness.json");
    write(
        &file,
        &moments(&[
            entry(Some("other"), "CVE-2022-1234", "2026-11-01T00:00:00Z"),
            entry(Some("shop"), LOG4J, "2026-11-13T09:30:00Z"),
        ]),
    );
    let before = fs::read(&file).expect("the file is read");
    let not_exploited = work.run(
        &["--awareness", path(&file)],
        &sbom(Some("shop"), &json!([widget()])),
    );
    assert_eq!(not_exploited.code, 1, "{}", not_exploited.stderr);
    let not_affected = json!({"state": "not_affected", "justification": "code_not_reachable"});
    let set_aside = work.run(
        &["--awareness", path(&file), "--format", "json"],
        &sbom_with(
            Some("shop"),
            &json!([log4j("2.14.1")]),
            &json!([{"id": LOG4J, "analysis": not_affected, "affects": [{"ref": "log4j-2.14.1"}]}]),
        ),
    );
    assert_eq!(set_aside.code, 0, "{}", set_aside.stderr);
    assert_eq!(fs::read(&file).expect("the file is read"), before);
}

// spec: AWR-12, MVX-8
#[test]
fn a_match_set_aside_carries_no_moment_of_awareness() {
    let work = Work::new();
    let not_affected = json!({"state": "not_affected", "justification": "code_not_reachable"});
    let run = work.run(
        &["--format", "json"],
        &sbom_with(
            Some("shop"),
            &json!([log4j("2.14.1")]),
            &json!([{"id": LOG4J, "analysis": not_affected, "affects": [{"ref": "log4j-2.14.1"}]}]),
        ),
    );
    assert_eq!(run.code, 0, "{}", run.stderr);
    let set_aside = &json_report(&run)["setAside"][0];
    assert_eq!(set_aside["name"], "log4j-core", "{set_aside}");
    assert!(set_aside.get("awareSince").is_none(), "{set_aside}");
    assert!(set_aside.get("deadlines").is_none(), "{set_aside}");
}

// spec: AWR-7
#[test]
fn records_null_for_an_sbom_naming_no_product_and_the_trimmed_name_of_a_product() {
    let work = Work::new();
    let file = work.file("awareness.json");
    let since = ["--aware-since", "2026-11-13T09:30:00Z"];
    let run = work.run(
        &[&["--awareness", path(&file)][..], &since].concat(),
        &sbom(None, &json!([log4j("2.14.1")])),
    );
    assert_eq!(run.code, 6, "{}", run.stderr);
    let run = work.run(
        &[&["--awareness", path(&file)][..], &since].concat(),
        &sbom(Some(" shop\n"), &json!([log4j("2.14.1")])),
    );
    assert_eq!(run.code, 6, "{}", run.stderr);
    assert_eq!(
        read(&file),
        moments(&[
            entry(None, LOG4J, "2026-11-13T09:30:00Z"),
            entry(Some("shop"), LOG4J, "2026-11-13T09:30:00Z"),
        ])
    );
    let text = fs::read_to_string(&file).expect("the file is read");
    assert!(text.starts_with("{\n  \""), "two spaces: {text}");
    assert!(text.ends_with("}\n"), "a final newline: {text:?}");
    let later = work.run(&["--awareness", path(&file)], &shop());
    assert!(
        later.stdout.contains(&format!(
            "    aware since 2026-11-13T09:30:00Z (from {})",
            path(&file)
        )),
        "{}",
        later.stdout
    );
}

// spec: AWR-7
#[test]
fn records_a_cve_of_two_matches_once() {
    let work = Work::new();
    let file = work.file("awareness.json");
    let run = work.run(
        &[
            "--awareness",
            path(&file),
            "--aware-since",
            "2026-11-13T09:30:00Z",
        ],
        &sbom(Some("shop"), &json!([log4j("2.14.1"), log4j("2.14.0")])),
    );
    assert_eq!(run.code, 6, "{}", run.stderr);
    assert_eq!(
        read(&file),
        moments(&[entry(Some("shop"), LOG4J, "2026-11-13T09:30:00Z")])
    );
}

// spec: AWR-8, AWR-9
#[test]
fn creates_the_file_and_its_parents_only_when_a_moment_is_recorded() {
    let work = Work::new();
    let file = work.file("a/b/awareness.json");
    let run = work.run(
        &["--awareness", path(&file)],
        &sbom(Some("shop"), &json!([widget()])),
    );
    assert_eq!(run.code, 1, "{}", run.stderr);
    assert!(!work.file("a").exists(), "nothing is created");
    let run = work.run(&["--awareness", path(&file)], &shop());
    assert_eq!(run.code, 6, "{}", run.stderr);
    let names: Vec<_> = fs::read_dir(work.file("a/b"))
        .expect("the directory is created")
        .map(|entry| entry.expect("an entry").file_name())
        .collect();
    assert_eq!(names, ["awareness.json"], "no temporary file left");
}

// spec: AWR-6, AWR-12
#[test]
fn without_the_option_every_match_takes_the_moment_of_the_run_and_no_file_is_written() {
    let work = Work::new();
    let records = work.file("records");
    let kev = kev_fixture();
    let cwd = TempDir::new().expect("a temporary directory");
    let run = run_in(
        cwd.path(),
        &[
            "match",
            "--osv",
            path(&records),
            "--kev",
            path(&kev),
            "--no-euvd",
            "--format",
            "json",
            "-",
        ],
        Some(&sbom(
            Some("shop"),
            &json!([log4j("2.14.1"), gateway(), widget()]),
        )),
    );
    assert_eq!(run.code, 6, "{}", run.stderr);
    let report = json_report(&run);
    assert!(report["awareSince"].is_string(), "{report}");
    assert_eq!(
        affected(&report, "log4j-core", "awareSince"),
        report["awareSince"]
    );
    assert_eq!(
        affected(&report, "gateway", "awareSince"),
        report["awareSince"]
    );
    assert_eq!(affected(&report, "widget", "awareSince"), Value::Null);
    assert_eq!(
        fs::read_dir(cwd.path())
            .expect("the directory is read")
            .count(),
        0,
        "no file is written"
    );
}

// spec: AWR-10, MCH-10
#[test]
fn refuses_a_file_of_moments_it_cannot_read_before_reading_the_sbom() {
    let work = Work::new();
    let file = work.file("awareness.json");
    let one = |product: &str, aware_since: &str| {
        serde_json::to_string(&moments(&[entry(Some(product), LOG4J, aware_since)])).unwrap()
    };
    let twice = serde_json::to_string(&moments(&[
        entry(Some("shop"), LOG4J, "2026-11-13T09:30:00Z"),
        entry(Some("shop"), LOG4J, "2026-11-14T09:30:00Z"),
    ]))
    .unwrap();
    for content in [
        "not JSON".to_owned(),
        "{}".to_owned(),
        r#"{"awareness": {}}"#.to_owned(),
        r#"{"awareness": [{"product": 1, "cve": "CVE-2021-44228", "awareSince": "2026-11-13T09:30:00Z"}]}"#
            .to_owned(),
        r#"{"awareness": [{"product": "shop", "awareSince": "2026-11-13T09:30:00Z"}]}"#.to_owned(),
        one("shop", "2026-11-13"),
        one("shop", "2026-11-13T25:00:00Z"),
        one("shop", "9999-12-30T00:00:01Z"),
        twice,
    ] {
        fs::write(&file, &content).expect("the file is written");
        // An SBOM that cannot be read: the file of moments is refused first.
        let run = work.run(&["--awareness", path(&file)], b"not an SBOM");
        assert_eq!(run.code, 3, "{content}: {}", run.stderr);
        assert_eq!(run.stdout, "", "{content}");
        assert!(
            run.stderr.starts_with(&format!("error: cannot read the moments of awareness {}: ", path(&file))),
            "{content}: {}",
            run.stderr
        );
        assert_eq!(run.stderr.lines().count(), 1, "{}", run.stderr);
        assert_eq!(fs::read_to_string(&file).expect("the file is read"), content);
    }
    let directory = work.file("records");
    let run = work.run(&["--awareness", path(&directory)], &shop());
    assert_eq!(run.code, 3, "{}", run.stderr);
    assert!(run.stderr.contains(path(&directory)), "{}", run.stderr);
}

// spec: AWR-11, AWR-9, MCH-10
#[test]
fn exits_with_7_and_writes_no_draft_when_the_file_cannot_be_written() {
    let work = Work::new();
    let regular = work.file("regular");
    fs::write(&regular, "a file").expect("the file is written");
    let file = regular.join("awareness.json");
    let drafts = work.file("drafts");
    let run = work.run(
        &["--awareness", path(&file), "--drafts", path(&drafts)],
        &shop(),
    );
    assert_eq!(run.code, 7, "{}", run.stderr);
    assert_eq!(run.stdout, "");
    assert!(
        run.stderr
            .starts_with("error: cannot write the moments of awareness ")
            && run.stderr.contains(path(&regular)),
        "{}",
        run.stderr
    );
    assert_eq!(run.stderr.lines().count(), 1, "{}", run.stderr);
    assert!(!drafts.exists(), "no draft is written");
}
