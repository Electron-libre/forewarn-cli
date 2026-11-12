//! Checking the completeness of an SBOM an existing tool produced (`specs/sbom-completeness.md`).

use std::fs::File;
use std::path::Path;

use rollcall_cyclonedx::read_json;
use rollcall_domain::completeness::{Field, check};

// spec: SBC-H1
#[test]
fn reports_the_gaps_of_the_sbom_of_syft() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/syft.cdx.json");
    let sbom = read_json(File::open(&path).expect("the syft fixture")).expect("a readable SBOM");
    let report = check(&sbom.components);
    let gaps: Vec<(&str, &[Field])> = report
        .incomplete()
        .iter()
        .map(|c| (c.name.as_str(), c.missing.as_slice()))
        .collect();
    let all: &[Field] = &[Field::Supplier, Field::License, Field::Hash];
    let no_hash_gap: &[Field] = &[Field::Supplier, Field::License];
    assert_eq!(
        gaps,
        [
            ("itoa", all),
            ("rollcall-fixture-sample", all),
            ("semver", all),
            ("/Cargo.lock", no_hash_gap),
        ]
    );
    assert!(!report.is_complete());
}
