//! `forewarn match` keeping the first-party components of an SBOM, the vendor's own code, out of the match
//! (`specs/cli-match.md`, MCH-42).

mod common;

use std::fs;
use std::path::Path;

use common::{bom, json_report, run};
use serde_json::{Value, json};
use tempfile::TempDir;

/// The SBOM `cdxgen` generated for a Maven project of two modules, `mod-a` and `mod-b` 1.0, nested in the product.
fn cdxgen_maven() -> Vec<u8> {
    fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../forewarn-cyclonedx/tests/fixtures/cdxgen-maven.cdx.json"),
    )
    .expect("the fixture is read")
}

/// A directory holding one OSV record affecting the Maven package `org.example.forewarn:mod-a` 1.0, as a published
/// package of that name would be.
fn record_naming_mod_a() -> TempDir {
    let directory = TempDir::new().expect("a temporary directory");
    let record = json!({
        "id": "GHSA-0000-0000-0000",
        "modified": "2026-01-01T00:00:00Z",
        "aliases": ["CVE-2026-0001"],
        "affected": [{
            "package": {"ecosystem": "Maven", "name": "org.example.forewarn:mod-a"},
            "versions": ["1.0"]
        }]
    });
    fs::write(
        directory.path().join("GHSA-0000-0000-0000.json"),
        record.to_string(),
    )
    .expect("the record is written");
    directory
}

fn reasons(report: &Value) -> Vec<(String, String)> {
    report["notEvaluated"]
        .as_array()
        .expect("notEvaluated")
        .iter()
        .map(|gap| {
            (
                gap["name"].as_str().expect("a name").to_owned(),
                gap["reason"].as_str().expect("a reason").to_owned(),
            )
        })
        .collect()
}

// spec: MCH-42, MCH-16, VMT-10, VMT-11
#[test]
fn a_module_of_the_product_named_like_a_vulnerable_package_is_not_matched() {
    let records = record_naming_mod_a();
    let osv = records.path().to_str().expect("UTF-8 path");
    let sbom = cdxgen_maven();
    let base = ["match", "--no-kev", "--no-euvd", "--osv", osv];

    let json = run(
        &[&base[..], &["--format", "json", "-"]].concat(),
        Some(&sbom),
    );
    let human = run(&[&base[..], &["-"]].concat(), Some(&sbom));

    assert_eq!(json.code, 0, "{}", json.stderr);
    let report = json_report(&json);
    assert_eq!(report["affected"], json!([]));
    let first_party = |name: &str| (name.to_owned(), "first-party".to_owned());
    assert_eq!(
        reasons(&report),
        [first_party("mod-b"), first_party("mod-a")]
    );
    assert_eq!(human.code, 0, "{}", human.stderr);
    assert!(
        human.stdout.contains("mod-a") && human.stdout.contains("first-party"),
        "{}",
        human.stdout
    );
}

// spec: MCH-42
#[test]
fn fetches_no_archive_for_an_ecosystem_only_first_party_components_use() {
    let cache = TempDir::new().expect("a temporary directory");
    let mut document: Value = serde_json::from_slice(&bom("1.6", &json!([]))).expect("JSON");
    document["metadata"] = json!({"component": {
        "type": "application",
        "name": "parent",
        "components": [{
            "type": "library",
            "name": "mod-a",
            "version": "1.0",
            "purl": "pkg:maven/org.example.forewarn/mod-a@1.0"
        }]
    }});
    let sbom = document.to_string().into_bytes();

    let run = run(
        &[
            "match",
            "--no-kev",
            "--no-euvd",
            "--refresh",
            "offline",
            "--cache",
            cache.path().to_str().expect("UTF-8 path"),
            "--format",
            "json",
            "-",
        ],
        Some(&sbom),
    );

    assert_eq!(run.code, 0, "{}", run.stderr);
    let report = json_report(&run);
    assert_eq!(report["osv"], json!([]));
    assert_eq!(
        reasons(&report),
        [("mod-a".to_owned(), "first-party".to_owned())]
    );
}
