//! Matching the SBOMs existing tools produced against known vulnerabilities (`specs/vulnerability-matching.md`).

use std::fs::File;
use std::path::Path;

use forewarn_cyclonedx::read_json;
use forewarn_domain::matching::match_components;
use forewarn_domain::vulnerability::{AffectedPackage, Event, Range, RangeKind, Vulnerability};

// spec: VMT-1, VMT-5
#[test]
fn matches_the_crates_of_a_cargo_cyclonedx_sbom() {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cargo-cyclonedx.cdx.json");
    let sbom = read_json(File::open(&path).expect("the fixture")).expect("a valid SBOM");
    let itoa = Vulnerability {
        id: "TEST-0001".into(),
        aliases: vec!["CVE-0000-0001".into()],
        source: "RUSTSEC".into(),
        withdrawn: false,
        affected: vec![AffectedPackage {
            ecosystem: "crates.io".into(),
            name: "itoa".into(),
            versions: vec![],
            ranges: vec![Range {
                kind: RangeKind::Semver,
                events: vec![Event::Introduced("0".into()), Event::Fixed("1.0.20".into())],
            }],
        }],
    };
    let report = match_components(&sbom.components, &[itoa]);
    let matched: Vec<(&str, &str)> = report
        .matches()
        .iter()
        .map(|m| (m.component.name.as_str(), m.vulnerability_id.as_str()))
        .collect();
    assert_eq!(matched, [("itoa", "TEST-0001")]);
    assert_eq!(report.not_evaluated(), [], "{:?}", report.not_evaluated());
}
