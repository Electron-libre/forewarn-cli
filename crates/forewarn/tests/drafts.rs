//! `forewarn match --drafts <dir>` writing the draft early warning of each actively exploited CVE to a file, driven
//! through the binary (`specs/cli-match-exploited.md`, MXL-27 to MXL-35), and the values of the SBOM and of the lists
//! that file holds (`specs/early-warning-draft.md`).

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use common::{Run, json_report, run, run_in};
use serde_json::{Value, json};
use tempfile::TempDir;

/// The KEV catalog of the KEV adapter's tests, naming `CVE-2021-44228` added on 2021-12-10.
fn kev_fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../forewarn-exploited/tests/fixtures/kev.json")
}

fn path(path: &Path) -> &str {
    path.to_str().expect("UTF-8 path")
}

const DRAFT: &str = "shop-CVE-2021-44228.md";

/// A directory holding an OSV record of `Log4Shell`, `CVE-2021-44228`, affecting `log4j-core` before 2.15.0, and one of
/// `CVE-2023-4966`, which the KEV fixture also names, affecting `com.example:gateway` before 2.0.0.
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
    let citrix = json!({
        "id": "GHSA-citrix-bleed",
        "modified": "2023-10-10T00:00:00Z",
        "aliases": ["CVE-2023-4966"],
        "affected": [{
            "package": {"ecosystem": "Maven", "name": "com.example:gateway"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}],
        }],
    });
    fs::write(
        directory.path().join("GHSA-citrix-bleed.json"),
        serde_json::to_vec(&citrix).expect("the record serializes"),
    )
    .expect("the record is written");
    directory
}

/// A 1.6 SBOM of the product `metadata` describes, holding `log4j-core` 2.14.1 when `exploited`, else `time` 0.1.43.
fn sbom(product: Option<Value>, exploited: bool) -> Vec<u8> {
    let component = if exploited {
        json!({"type": "library", "name": "log4j-core", "version": "2.14.1",
               "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"})
    } else {
        json!({"type": "library", "name": "time", "version": "0.1.43", "purl": "pkg:cargo/time@0.1.43"})
    };
    let mut bom = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [component],
    });
    if let Some(product) = product {
        bom["metadata"] = json!({"component": product});
    }
    serde_json::to_vec(&bom).expect("the SBOM serializes")
}

/// The SBOM of the product `shop` 2.1.0 made by `Acme`, with `log4j-core` 2.14.1.
fn shop() -> Vec<u8> {
    sbom(
        Some(
            json!({"type": "application", "name": "shop", "version": "2.1.0",
                    "manufacturer": {"name": "Acme"}}),
        ),
        true,
    )
}

/// The arguments of a deterministic `forewarn match` of standard input against `Log4Shell` and the KEV fixture.
fn match_args<'a>(records: &'a Path, kev: &'a Path, extra: &[&'a str]) -> Vec<&'a str> {
    let mut args = vec![
        "match",
        "--osv",
        path(records),
        "--kev",
        path(kev),
        "--no-euvd",
        "--aware-since",
        "2026-11-13T09:30:00Z",
        "--now",
        "2026-11-13T10:00:00Z",
    ];
    args.extend(extra);
    args.push("-");
    args
}

/// Runs `forewarn match` with `extra` on `sbom`.
fn matched(extra: &[&str], sbom: &[u8]) -> Run {
    let records = log4j_records();
    let kev = kev_fixture();
    run(&match_args(records.path(), &kev, extra), Some(sbom))
}

/// The names of the entries of a directory, sorted.
fn entries(directory: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(directory)
        .expect("the directory is read")
        .map(|entry| {
            entry
                .expect("an entry")
                .file_name()
                .into_string()
                .expect("a UTF-8 name")
        })
        .collect();
    names.sort();
    names
}

// spec: MXL-27, MXL-31
#[test]
fn the_draft_of_an_exploited_cve_is_written_to_a_file_named_after_the_product_and_the_cve() {
    let out = TempDir::new().expect("a temporary directory");
    let run = matched(&["--drafts", path(out.path())], &shop());
    assert_eq!(run.code, 6, "{}", run.stderr);
    assert_eq!(entries(out.path()), [DRAFT]);
    let draft = fs::read_to_string(out.path().join(DRAFT)).expect("the draft is written");
    assert!(
        draft.starts_with("# Draft CRA early warning: CVE\\-2021\\-44228\n"),
        "{draft}"
    );
    for expected in [
        "- **6. Product Name**: shop\n",
        "- **4. Manufacturer name**: Acme",
        "log4j\\-core",
        "- Aware since: 2026-11-13T09:30:00Z\n",
        "- Early warning due by: 2026-11-14T09:30:00Z\n",
        "- Notification due by: 2026-11-16T09:30:00Z\n",
        "- Final report due: 14 days after a corrective or mitigating measure is available\n",
    ] {
        assert!(draft.contains(expected), "{expected} in {draft}");
    }
}

// spec: MXL-29, MXL-34
#[test]
fn a_rerun_replaces_the_draft_of_the_same_cve_and_leaves_no_temporary_file() {
    let out = TempDir::new().expect("a temporary directory");
    assert_eq!(matched(&["--drafts", path(out.path())], &shop()).code, 6);
    let run = matched(
        &[
            "--drafts",
            path(out.path()),
            "--measure-available",
            "2026-11-15T17:00:00Z",
        ],
        &shop(),
    );
    assert_eq!(run.code, 6, "{}", run.stderr);
    assert_eq!(entries(out.path()), [DRAFT]);
    let draft = fs::read_to_string(out.path().join(DRAFT)).expect("the draft is written");
    assert!(
        draft.contains("- Final report due by: 2026-11-29T17:00:00Z\n"),
        "{draft}"
    );
}

// spec: MXL-30
#[test]
fn no_draft_is_written_and_no_directory_created_without_an_exploited_match() {
    let parent = TempDir::new().expect("a temporary directory");
    let out = parent.path().join("drafts");
    let run = matched(&["--drafts", path(&out)], &sbom(None, false));
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert!(!out.exists(), "the directory of the drafts is not created");
}

// spec: MXL-30
#[test]
fn no_draft_is_written_without_the_option() {
    let cwd = TempDir::new().expect("a temporary directory");
    let records = log4j_records();
    let kev = kev_fixture();
    let run = run_in(
        cwd.path(),
        &match_args(records.path(), &kev, &[]),
        Some(&shop()),
    );
    assert_eq!(run.code, 6, "{}", run.stderr);
    assert!(entries(cwd.path()).is_empty(), "{:?}", entries(cwd.path()));
}

// spec: MXL-31
#[test]
fn the_file_name_keeps_only_the_safe_characters_of_the_first_100_of_the_product_name() {
    let draft_name = |product: Option<Value>| {
        let out = TempDir::new().expect("a temporary directory");
        let run = matched(&["--drafts", path(out.path())], &sbom(product, true));
        assert_eq!(run.code, 6, "{}", run.stderr);
        entries(out.path())
    };
    assert_eq!(
        draft_name(Some(json!({"type": "application", "name": "../My Shop/1"}))),
        [".._My_Shop_1-CVE-2021-44228.md"]
    );
    assert_eq!(draft_name(None), ["CVE-2021-44228.md"]);
    assert_eq!(
        draft_name(Some(json!({"type": "application", "name": " shop\n"}))),
        [DRAFT]
    );
    assert_eq!(
        draft_name(Some(json!({"type": "application", "name": "   "}))),
        ["CVE-2021-44228.md"]
    );
    assert_eq!(
        draft_name(Some(
            json!({"type": "application", "name": "é".repeat(150)})
        )),
        [format!("{}-CVE-2021-44228.md", "_".repeat(100))]
    );
}

// spec: MXL-32
#[test]
fn the_directory_is_created_with_its_parents_and_other_files_are_left_untouched() {
    let parent = TempDir::new().expect("a temporary directory");
    let out = parent.path().join("a/b/c");
    let run = matched(&["--drafts", path(&out)], &shop());
    assert_eq!(run.code, 6, "{}", run.stderr);
    assert_eq!(entries(&out), [DRAFT]);

    fs::write(out.join("notes.md"), "my notes").expect("a file of the vendor");
    assert_eq!(matched(&["--drafts", path(&out)], &shop()).code, 6);
    assert_eq!(entries(&out), ["notes.md", DRAFT]);
    assert_eq!(
        fs::read_to_string(out.join("notes.md")).expect("read"),
        "my notes"
    );
}

// spec: MXL-33, MCH-10
#[test]
fn a_draft_directory_that_is_a_file_exits_with_7_and_prints_no_report() {
    let parent = TempDir::new().expect("a temporary directory");
    let file = parent.path().join("drafts");
    fs::write(&file, "").expect("a regular file");
    let run = matched(&["--drafts", path(&file)], &shop());
    assert_eq!(run.code, 7, "{}", run.stderr);
    assert_eq!(run.stdout, "");
    assert_eq!(run.stderr.lines().count(), 1, "{}", run.stderr);
    assert!(run.stderr.contains(path(&file)), "{}", run.stderr);
}

// spec: MXL-33, MXL-34
#[test]
fn a_draft_that_cannot_be_renamed_exits_with_7_and_leaves_no_temporary_file() {
    let out = TempDir::new().expect("a temporary directory");
    // A directory in the place of the draft: the rename over it fails.
    fs::create_dir(out.path().join(DRAFT)).expect("a directory");
    fs::write(out.path().join(DRAFT).join("keep"), "").expect("a file in it");
    let run = matched(&["--drafts", path(out.path())], &shop());
    assert_eq!(run.code, 7, "{}", run.stderr);
    assert_eq!(run.stdout, "");
    assert!(run.stderr.contains(DRAFT), "{}", run.stderr);
    assert_eq!(entries(out.path()), [DRAFT]);
}

// spec: MXL-H6, MXL-28, MXL-35
#[test]
fn the_report_names_the_draft_written_and_a_rerun_with_the_measure_replaces_it() {
    let out = TempDir::new().expect("a temporary directory");
    let draft = out.path().join(DRAFT);
    let run = matched(&["--drafts", path(out.path())], &shop());
    assert_eq!(run.code, 6, "{}", run.stderr);
    let expected = format!(
        "Draft early warnings (1):\n  CVE-2021-44228: {}\n",
        path(&draft)
    );
    assert!(run.stdout.contains(&expected), "{}", run.stdout);
    let affected = run.stdout.find("Affected (").expect("the matches");
    let not_evaluated = run.stdout.find("Not evaluated (").expect("the gaps");
    let drafts = run.stdout.find("Draft early warnings").expect("the drafts");
    assert!(
        affected < drafts && drafts < not_evaluated,
        "{}",
        run.stdout
    );
    let written = fs::read_to_string(&draft).expect("the draft is written");
    assert!(
        written.contains("- Early warning due by: 2026-11-14T09:30:00Z\n"),
        "{written}"
    );

    let rerun = matched(
        &[
            "--drafts",
            path(out.path()),
            "--measure-available",
            "2026-11-15T17:00:00Z",
        ],
        &shop(),
    );
    assert_eq!(rerun.code, 6, "{}", rerun.stderr);
    assert!(rerun.stdout.contains(&expected), "{}", rerun.stdout);
    assert_eq!(entries(out.path()), [DRAFT]);
    let written = fs::read_to_string(&draft).expect("the draft is replaced");
    assert!(
        written.contains("- Final report due by: 2026-11-29T17:00:00Z\n"),
        "{written}"
    );
}

// spec: MXL-27, MXL-28, MCH-16
#[test]
fn the_json_report_gives_the_draft_of_each_exploited_cve_in_the_order_of_the_matches() {
    let out = TempDir::new().expect("a temporary directory");
    let mut bom: Value = serde_json::from_slice(&shop()).expect("JSON");
    bom["components"]
        .as_array_mut()
        .expect("components")
        .insert(
            0,
            json!({"type": "library", "name": "gateway", "version": "1.0.0",
                   "purl": "pkg:maven/com.example/gateway@1.0.0"}),
        );
    let bom = serde_json::to_vec(&bom).expect("the SBOM serializes");
    let run = matched(&["--drafts", path(out.path()), "--format", "json"], &bom);
    assert_eq!(run.code, 6, "{}", run.stderr);
    let report = json_report(&run);
    let cves: Vec<&Value> = report["affected"]
        .as_array()
        .expect("an array")
        .iter()
        .map(|found| &found["exploited"][0]["cve"])
        .collect();
    let drafts: Vec<Value> = cves
        .iter()
        .map(|cve| {
            let cve = cve.as_str().expect("a CVE");
            json!({"cve": cve, "path": path(&out.path().join(format!("shop-{cve}.md")))})
        })
        .collect();
    assert_eq!(drafts.len(), 2, "{report:#}");
    assert_eq!(report["drafts"], Value::Array(drafts));
    assert_eq!(
        entries(out.path()),
        ["shop-CVE-2021-44228.md", "shop-CVE-2023-4966.md"]
    );
}

// spec: MXL-35, MCH-16
#[test]
fn without_the_option_the_reports_say_nothing_of_drafts() {
    let human = matched(&[], &shop());
    assert_eq!(human.code, 6, "{}", human.stderr);
    assert!(!human.stdout.contains("Draft"), "{}", human.stdout);
    let json = matched(&["--format", "json"], &shop());
    assert_eq!(json_report(&json)["drafts"], json!([]));
}

// spec: MXL-35, MCH-18
#[test]
fn the_path_of_a_draft_is_printed_with_its_control_characters_escaped() {
    let parent = TempDir::new().expect("a temporary directory");
    let out = parent.path().join("a\nb");
    let run = matched(&["--drafts", path(&out)], &shop());
    assert_eq!(run.code, 6, "{}", run.stderr);
    let printed = format!("{}/a\\nb/{DRAFT}\n", path(parent.path()));
    assert!(run.stdout.contains(&printed), "{}", run.stdout);
}

// spec: EWD-8
#[test]
fn the_draft_names_the_euvd_id_of_the_euvd_record_naming_its_cve() {
    let records = log4j_records();
    let lists = TempDir::new().expect("a temporary directory");
    let euvd = lists.path().join("euvd.json");
    let list = json!({"items": [{
        "id": "EUVD-2021-0001",
        "aliases": "CVE-2021-44228\n",
        "exploitedSince": "Dec 10, 2021, 12:00:00 AM",
    }]});
    fs::write(&euvd, list.to_string()).expect("the list is written");
    let out = TempDir::new().expect("a temporary directory");
    let args = [
        "match",
        "--osv",
        path(records.path()),
        "--no-kev",
        "--euvd",
        path(&euvd),
        "--aware-since",
        "2026-11-13T09:30:00Z",
        "--drafts",
        path(out.path()),
        "-",
    ];

    let run = run(&args, Some(&shop()));

    assert_eq!(run.code, 6, "{}", run.stderr);
    let draft = fs::read_to_string(out.path().join(DRAFT)).expect("the draft is written");
    assert!(
        draft.contains("- **v20. EUVD ID**: EUVD\\-2021\\-0001\n"),
        "{draft}"
    );
}

// spec: EWD-3, EWD-14, SBR-12
#[test]
fn a_manufacturer_given_only_by_its_contact_is_not_named_in_the_draft() {
    let product = json!({"type": "application", "name": "shop", "version": "2.1.0",
                         "manufacturer": {"contact": [{"email": "security@acme.example"}]}});
    let out = TempDir::new().expect("a temporary directory");

    let run = matched(&["--drafts", path(out.path())], &sbom(Some(product), true));

    assert_eq!(run.code, 6, "{}", run.stderr);
    let draft = fs::read_to_string(out.path().join(DRAFT)).expect("the draft is written");
    assert!(
        draft.contains("- **4. Manufacturer name**: not in the SBOM"),
        "{draft}"
    );
    assert!(!draft.contains("acme"), "{draft}");
}

// spec: EWD-16
#[test]
fn a_component_name_that_hides_text_or_forges_markdown_is_written_escaped() {
    let mut bom: Value = serde_json::from_slice(&shop()).expect("JSON");
    bom["components"][0]["name"] = json!("a|b\u{202e}log4j\u{13441}-core\n# Title");
    let bom = serde_json::to_vec(&bom).expect("the SBOM serializes");
    let out = TempDir::new().expect("a temporary directory");

    let run = matched(&["--drafts", path(out.path())], &bom);

    assert_eq!(run.code, 6, "{}", run.stderr);
    let draft = fs::read_to_string(out.path().join(DRAFT)).expect("the draft is written");
    assert!(
        draft.contains(
            "\n  - a\\|b\\\\u\\{202e\\}log4j\\\\u\\{13441\\}\\-core\\\\n\\# Title 2\\.14\\.1, "
        ),
        "{draft}"
    );
    assert!(!draft.contains(['\u{202e}', '\u{13441}']), "{draft:?}");
    assert!(!draft.contains("a|b"), "{draft}");
    assert!(
        !draft.lines().any(|line| line.starts_with("# Title")),
        "{draft}"
    );
}

// spec: EWD-16
#[test]
fn a_backslash_typed_in_the_sbom_reads_apart_from_an_escaped_character() {
    let mut bom: Value = serde_json::from_slice(&shop()).expect("JSON");
    bom["components"][0]["name"] = json!("a\\u{202e}b\u{202e}c");
    let bom = serde_json::to_vec(&bom).expect("the SBOM serializes");
    let out = TempDir::new().expect("a temporary directory");

    let run = matched(&["--drafts", path(out.path())], &bom);

    assert_eq!(run.code, 6, "{}", run.stderr);
    let draft = fs::read_to_string(out.path().join(DRAFT)).expect("the draft is written");
    // Rendered: `a\\u{202e}b\u{202e}c`, the text typed apart from the escape.
    assert!(
        draft.contains("\n  - a\\\\\\\\u\\{202e\\}b\\\\u\\{202e\\}c 2\\.14\\.1, "),
        "{draft}"
    );
}
