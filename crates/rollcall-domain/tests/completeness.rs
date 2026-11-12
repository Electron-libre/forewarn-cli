//! The completeness check of the components of an SBOM (`specs/sbom-completeness.md`).

use rollcall_domain::completeness::{CHECKED_FIELDS, Field, IncompleteComponent, check};
use rollcall_domain::sbom::{Component, Hash};

fn hash(algorithm: &str, value: &str) -> Hash {
    Hash {
        algorithm: algorithm.into(),
        value: value.into(),
    }
}

/// A component with every checked field.
fn complete(name: &str) -> Component {
    Component {
        name: name.into(),
        version: Some("1.0.0".into()),
        purl: Some(format!("pkg:cargo/{name}@1.0.0")),
        supplier: Some("Acme".into()),
        licenses: vec!["MIT".into()],
        hashes: vec![hash("SHA-256", "abcd")],
        ..Component::default()
    }
}

fn missing(component: &Component) -> Vec<Field> {
    let report = check(std::slice::from_ref(component));
    report
        .incomplete()
        .first()
        .map(|c| c.missing.clone())
        .unwrap_or_default()
}

// spec: SBC-1, SBC-6
#[test]
fn reports_a_component_with_its_missing_fields_in_order() {
    let bare = Component {
        name: "itoa".into(),
        version: Some("1.0.19".into()),
        purl: Some("pkg:cargo/itoa@1.0.19".into()),
        ..Component::default()
    };
    let report = check(&[bare]);
    assert_eq!(
        report.incomplete(),
        [IncompleteComponent {
            name: "itoa".into(),
            version: Some("1.0.19".into()),
            purl: Some("pkg:cargo/itoa@1.0.19".into()),
            missing: vec![Field::Supplier, Field::License, Field::Hash],
        }]
    );
    assert!(!report.is_complete());
}

// spec: SBC-6
#[test]
fn a_reported_component_without_version_or_purl_carries_none() {
    let report = check(&[Component {
        name: "/Cargo.lock".into(),
        ..Component::default()
    }]);
    let reported = &report.incomplete()[0];
    assert_eq!(reported.name, "/Cargo.lock");
    assert_eq!(reported.version, None);
    assert_eq!(reported.purl, None);
}

// spec: SBC-2, SBC-3, SBC-H2
#[test]
fn an_sbom_whose_components_have_every_field_is_complete() {
    let report = check(&[complete("itoa"), complete("semver")]);
    assert_eq!(report.incomplete(), []);
    assert!(report.is_complete());
}

// spec: SBC-3
#[test]
fn an_sbom_with_no_component_is_complete() {
    let report = check(&[]);
    assert_eq!(report.incomplete(), []);
    assert!(report.is_complete());
}

// spec: SBC-4
#[test]
fn every_creator_field_makes_the_supplier_present() {
    let no_supplier = Component {
        supplier: None,
        ..complete("a")
    };
    assert_eq!(missing(&no_supplier), [Field::Supplier]);
    for with_creator in [
        Component {
            manufacturer: Some("Acme".into()),
            ..no_supplier.clone()
        },
        Component {
            authors: vec!["Jane Doe".into()],
            ..no_supplier.clone()
        },
        Component {
            publisher: Some("Acme".into()),
            ..no_supplier.clone()
        },
    ] {
        assert_eq!(missing(&with_creator), []);
    }
}

// spec: SBC-4
#[test]
fn a_blank_value_counts_as_absent() {
    let blank = Component {
        supplier: Some("  ".into()),
        authors: vec![String::new()],
        licenses: vec![" ".into()],
        hashes: vec![hash("SHA-256", " ")],
        ..complete("a")
    };
    assert_eq!(
        missing(&blank),
        [Field::Supplier, Field::License, Field::Hash]
    );
}

// spec: SBC-4
#[test]
fn an_expression_is_a_license_but_noassertion_is_not() {
    let with_license = |license: &str| Component {
        licenses: vec![license.into()],
        ..complete("a")
    };
    assert_eq!(missing(&with_license("MIT OR Apache-2.0")), []);
    assert_eq!(missing(&with_license("NONE")), []);
    assert_eq!(missing(&with_license("NOASSERTION")), [Field::License]);
    let noassertion_then_mit = Component {
        licenses: vec!["NOASSERTION".into(), "MIT".into()],
        ..complete("a")
    };
    assert_eq!(missing(&noassertion_then_mit), []);
}

// spec: SBC-4, SBC-5
#[test]
fn only_a_listed_algorithm_with_a_value_makes_the_hash_present() {
    let with_hash = |algorithm: &str, value: &str| Component {
        hashes: vec![hash(algorithm, value)],
        ..complete("a")
    };
    for algorithm in [
        "MD5",
        "SHA-1",
        "SHA-256",
        "SHA-384",
        "SHA-512",
        "SHA3-256",
        "SHA3-384",
        "SHA3-512",
        "BLAKE2b-256",
        "BLAKE2b-384",
        "BLAKE2b-512",
        "BLAKE3",
        "sha-256",
        "blake2B-512",
    ] {
        assert_eq!(missing(&with_hash(algorithm, "abcd")), [], "{algorithm}");
    }
    assert_eq!(missing(&with_hash("CRC32", "abcd")), [Field::Hash]);
    assert_eq!(missing(&with_hash("SHA-256", "")), [Field::Hash]);
    let crc_then_sha = Component {
        hashes: vec![hash("CRC32", "abcd"), hash("SHA-512", "ef01")],
        ..complete("a")
    };
    assert_eq!(missing(&crc_then_sha), []);
}

// spec: SBC-7
#[test]
fn keeps_the_order_of_the_sbom_and_reports_duplicates_twice() {
    let bare = |name: &str| Component {
        name: name.into(),
        ..Component::default()
    };
    let report = check(&[bare("b"), complete("ok"), bare("a"), bare("b")]);
    let names: Vec<&str> = report
        .incomplete()
        .iter()
        .map(|c| c.name.as_str())
        .collect();
    assert_eq!(names, ["b", "a", "b"]);
}

#[test]
fn the_checked_fields_are_supplier_license_and_hash() {
    assert_eq!(
        CHECKED_FIELDS,
        [Field::Supplier, Field::License, Field::Hash]
    );
}
