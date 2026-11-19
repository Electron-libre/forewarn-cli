//! The source package of a component, read from the properties `trivy` writes (`specs/sbom-reading.md`, SBR-17).

use forewarn_cyclonedx::read_json;
use forewarn_domain::sbom::SourcePackage;
use serde_json::{Value, json};

/// The source package read for a component carrying these `aquasecurity:trivy:` properties, given as
/// `(suffix, value)`.
fn source_of(properties: &[(&str, &str)]) -> Option<SourcePackage> {
    let properties: Vec<Value> = properties
        .iter()
        .map(|(suffix, value)| json!({"name": format!("aquasecurity:trivy:{suffix}"), "value": value}))
        .collect();
    let document = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [{"type": "library", "name": "libc6", "properties": properties}],
    });
    let sbom = read_json(document.to_string().as_bytes()).expect("readable");
    sbom.components[0].source.clone()
}

fn source(name: &str, version: Option<&str>) -> SourcePackage {
    SourcePackage {
        name: name.to_owned(),
        version: version.map(ToOwned::to_owned),
    }
}

// spec: SBR-17
#[test]
fn reads_the_source_package_with_its_epoch_version_and_release() {
    assert_eq!(
        source_of(&[
            ("SrcEpoch", "1"),
            ("SrcName", "shadow"),
            ("SrcRelease", "1+deb12u2"),
            ("SrcVersion", "4.13+dfsg1"),
        ]),
        Some(source("shadow", Some("1:4.13+dfsg1-1+deb12u2")))
    );
    assert_eq!(
        source_of(&[
            ("SrcName", "glibc"),
            ("SrcRelease", "9+deb12u14"),
            ("SrcVersion", "2.36"),
        ]),
        Some(source("glibc", Some("2.36-9+deb12u14")))
    );
}

// spec: SBR-17
#[test]
fn leaves_out_an_epoch_of_zero_and_an_absent_release() {
    assert_eq!(
        source_of(&[
            ("SrcName", "bash"),
            ("SrcVersion", "5.2.15"),
            ("SrcEpoch", "0")
        ]),
        Some(source("bash", Some("5.2.15")))
    );
    assert_eq!(
        source_of(&[
            ("SrcName", " bash "),
            ("SrcVersion", " 5.2.15 "),
            ("SrcEpoch", " "),
            ("SrcRelease", "  "),
        ]),
        Some(source("bash", Some("5.2.15")))
    );
}

// spec: SBR-17
#[test]
fn reads_a_source_package_without_a_version() {
    assert_eq!(
        source_of(&[("SrcName", "pam"), ("SrcRelease", "6")]),
        Some(source("pam", None))
    );
}

// spec: SBR-17
#[test]
fn reads_no_source_package_without_a_source_name() {
    assert_eq!(source_of(&[("SrcVersion", "2.36")]), None);
    assert_eq!(source_of(&[("SrcName", " "), ("SrcVersion", "2.36")]), None);
    assert_eq!(source_of(&[]), None);
}

// spec: SBR-17
#[test]
fn reads_the_first_property_of_a_repeated_name() {
    assert_eq!(
        source_of(&[
            ("SrcName", "glibc"),
            ("SrcName", "other"),
            ("SrcVersion", "2.36"),
            ("SrcVersion", "9.9"),
        ]),
        Some(source("glibc", Some("2.36")))
    );
}
