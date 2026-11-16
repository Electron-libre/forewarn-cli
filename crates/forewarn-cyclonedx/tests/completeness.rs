//! Checking the completeness of the SBOMs existing tools produced (`specs/sbom-completeness.md`).

use std::fs::File;
use std::path::Path;

use forewarn_cyclonedx::read_json;
use forewarn_domain::completeness::{CompletenessReport, Field, check};

const ALL: &[Field] = &[Field::Supplier, Field::License, Field::Hash];
const NO_HASH_GAP: &[Field] = &[Field::Supplier, Field::License];

fn check_fixture(name: &str) -> CompletenessReport {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    let file = File::open(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let sbom = read_json(file).unwrap_or_else(|e| panic!("{name}: {e}"));
    check(&sbom.components)
}

fn gaps(report: &CompletenessReport) -> Vec<(&str, &[Field])> {
    report
        .incomplete()
        .iter()
        .map(|c| (c.name.as_str(), c.missing.as_slice()))
        .collect()
}

// spec: SBC-H1, SBC-H3
#[test]
fn reports_the_gaps_of_the_sbom_of_syft_and_leaves_its_lock_file_out() {
    let report = check_fixture("syft.cdx.json");
    assert_eq!(
        gaps(&report),
        [
            ("itoa", ALL),
            ("rollcall-fixture-sample", ALL),
            ("semver", ALL),
        ]
    );
    assert!(!report.is_complete());
    let not_checked: Vec<&str> = report
        .not_checked()
        .iter()
        .map(|c| c.name.as_str())
        .collect();
    assert_eq!(not_checked, ["/Cargo.lock"]);
}

// spec: SBC-1, SBC-4
#[test]
fn reports_the_gaps_of_the_sbom_of_cdxgen() {
    let report = check_fixture("cdxgen.cdx.json");
    assert_eq!(
        gaps(&report),
        [
            ("itoa", NO_HASH_GAP),
            ("rollcall-fixture-sample", ALL),
            ("semver", NO_HASH_GAP),
        ]
    );
}

// spec: SBC-2, SBC-3, SBC-4
#[test]
fn the_sbom_of_cargo_cyclonedx_is_complete_through_its_authors_and_expressions() {
    let report = check_fixture("cargo-cyclonedx.cdx.json");
    assert_eq!(gaps(&report), []);
    assert!(report.is_complete());
}
