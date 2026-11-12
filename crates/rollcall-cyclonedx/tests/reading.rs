//! Reading a CycloneDX JSON SBOM into the domain (`specs/sbom-reading.md`).

use rollcall_cyclonedx::{ReadError, read_json};
use rollcall_domain::sbom::{Component, Hash, Sbom, SpecVersion};
use serde_json::{Value, json};

fn bom(spec_version: &str, components: &Value) -> Value {
    json!({
        "bomFormat": "CycloneDX",
        "specVersion": spec_version,
        "version": 1,
        "components": components,
    })
}

fn read(document: &Value) -> Result<Sbom, ReadError> {
    read_json(document.to_string().as_bytes())
}

fn named(name: &str) -> Component {
    Component {
        name: name.to_owned(),
        ..Component::default()
    }
}

fn names(sbom: &Sbom) -> Vec<&str> {
    sbom.components.iter().map(|c| c.name.as_str()).collect()
}

// spec: SBR-1
#[test]
fn reads_versions_1_6_and_1_7_with_no_flag() {
    for (text, version) in [
        ("1.6", SpecVersion::new(1, 6)),
        ("1.7", SpecVersion::new(1, 7)),
    ] {
        let sbom = read(&bom(text, &json!([{ "type": "library", "name": "serde" }])))
            .unwrap_or_else(|e| panic!("{text}: {e}"));
        assert_eq!(sbom.spec_version, version);
        assert!(!sbom.spec_version.is_below_bsi_minimum(), "{text}");
        assert_eq!(sbom.components, vec![named("serde")]);
    }
}

// spec: SBR-1
#[test]
fn reads_an_sbom_with_no_components_as_an_empty_list() {
    let document = json!({ "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1 });
    let sbom = read(&document).expect("readable");
    assert_eq!(sbom.components, Vec::<Component>::new());
}

// spec: SBR-2, SBR-H2
#[test]
fn reads_versions_1_3_to_1_5_flagged_below_the_bsi_minimum() {
    for (text, minor) in [("1.3", 3), ("1.4", 4), ("1.5", 5)] {
        let sbom = read(&bom(
            text,
            &json!([{ "type": "library", "name": "serde", "version": "1.0.228" }]),
        ))
        .unwrap_or_else(|e| panic!("{text}: {e}"));
        assert_eq!(sbom.spec_version, SpecVersion::new(1, minor));
        assert!(sbom.spec_version.is_below_bsi_minimum(), "{text}");
        assert_eq!(names(&sbom), ["serde"]);
    }
}

// spec: SBR-5
#[test]
fn maps_the_fields_of_a_component() {
    let document = bom(
        "1.6",
        &json!([{
            "type": "library",
            "name": "serde",
            "version": "1.0.228",
            "purl": "pkg:cargo/serde@1.0.228",
            "supplier": { "name": "Serde Team" },
            "author": "David Tolnay",
            "authors": [{ "name": "Serde Contributors" }, { "email": "anonymous@example.com" }],
            "manufacturer": { "name": "Serde Foundry" },
            "publisher": "crates.io",
            "licenses": [{ "license": { "id": "MIT" } }, { "license": { "name": "Custom terms" } }],
            "hashes": [{ "alg": "SHA-256", "content": "aa".repeat(32) }]
        }, {
            "type": "library",
            "name": "dual",
            "licenses": [{ "expression": "MIT OR Apache-2.0" }]
        }]),
    );
    let sbom = read(&document).expect("readable");
    assert_eq!(
        sbom.components,
        vec![
            Component {
                name: "serde".into(),
                version: Some("1.0.228".into()),
                purl: Some("pkg:cargo/serde@1.0.228".into()),
                supplier: Some("Serde Team".into()),
                manufacturer: Some("Serde Foundry".into()),
                authors: vec![
                    "David Tolnay".into(),
                    "Serde Contributors".into(),
                    "anonymous@example.com".into(),
                ],
                publisher: Some("crates.io".into()),
                licenses: vec!["MIT".into(), "Custom terms".into()],
                hashes: vec![Hash {
                    algorithm: "SHA-256".into(),
                    value: "aa".repeat(32),
                }],
            },
            Component {
                licenses: vec!["MIT OR Apache-2.0".into()],
                ..named("dual")
            },
        ]
    );
}

fn creators(component: &Value) -> Component {
    let mut sbom = read(&bom("1.6", &json!([component]))).expect("readable");
    sbom.components.remove(0)
}

// spec: SBR-5
#[test]
fn identifies_an_organization_with_no_name_by_its_url_then_its_contact_email() {
    let contact = json!([{ "name": "Jane Doe", "phone": "+33 1 00 00 00 00" }, { "email": "sec@example.com" }]);
    let by_url = creators(&json!({
        "type": "library",
        "name": "a",
        "supplier": { "url": ["  ", "https://example.com"], "contact": contact },
        "manufacturer": { "name": "  ", "url": ["https://maker.example"] },
    }));
    assert_eq!(by_url.supplier.as_deref(), Some("https://example.com"));
    assert_eq!(
        by_url.manufacturer.as_deref(),
        Some("https://maker.example")
    );
    let by_email = creators(&json!({
        "type": "library",
        "name": "b",
        "supplier": { "contact": contact },
        "manufacturer": { "contact": [{ "email": "maker@example.com" }] },
    }));
    assert_eq!(by_email.supplier.as_deref(), Some("sec@example.com"));
    assert_eq!(by_email.manufacturer.as_deref(), Some("maker@example.com"));
}

// spec: SBR-5
#[test]
fn an_organization_known_only_by_a_contact_name_or_phone_has_no_identity() {
    let component = creators(&json!({
        "type": "library",
        "name": "a",
        "supplier": { "contact": [{ "name": "Jane Doe", "phone": "+33 1 00 00 00 00" }] },
    }));
    assert_eq!(component.supplier, None);
}

// spec: SBR-5
#[test]
fn identifies_an_author_with_no_name_by_its_email() {
    let component = creators(&json!({
        "type": "library",
        "name": "a",
        "authors": [
            { "email": "dev@example.com" },
            { "name": " ", "email": "other@example.com" },
            { "phone": "+33 1 00 00 00 00" }
        ],
    }));
    assert_eq!(component.authors, ["dev@example.com", "other@example.com"]);
}

// spec: SBR-5
#[test]
fn keeps_a_component_with_no_supplier_licenses_nor_hashes() {
    let sbom =
        read(&bom("1.6", &json!([{ "type": "library", "name": "bare" }]))).expect("readable");
    assert_eq!(sbom.components, vec![named("bare")]);
}

// spec: SBR-6
#[test]
fn flattens_nested_components_in_document_order() {
    let document = bom(
        "1.6",
        &json!([
            { "type": "application", "name": "a", "components": [
                { "type": "library", "name": "a1", "components": [
                    { "type": "library", "name": "a1x" }
                ] },
                { "type": "library", "name": "a2" }
            ] },
            { "type": "library", "name": "b" }
        ]),
    );
    let sbom = read(&document).expect("readable");
    assert_eq!(names(&sbom), ["a", "a1", "a1x", "a2", "b"]);
}

// spec: SBR-8
#[test]
fn keeps_a_component_of_an_unknown_type_or_hash_algorithm() {
    let document = bom(
        "1.6",
        &json!([{
            "type": "quantum-widget",
            "name": "odd",
            "hashes": [{ "alg": "SHA-999", "content": "abc" }],
            "notInTheSpec": true
        }]),
    );
    let sbom = read(&document).expect("readable");
    assert_eq!(
        sbom.components,
        vec![Component {
            hashes: vec![Hash {
                algorithm: "SHA-999".into(),
                value: "abc".into(),
            }],
            ..named("odd")
        }]
    );
}

fn refused(input: &[u8]) -> ReadError {
    match read_json(input) {
        Ok(sbom) => panic!("read: {sbom:?}"),
        Err(e) => e,
    }
}

// spec: SBR-3, SBR-7
#[test]
fn refuses_an_input_that_is_not_json() {
    let error = refused(b"<bom/>");
    assert!(matches!(error, ReadError::NotJson(_)), "{error:?}");
    assert!(error.to_string().starts_with("not JSON"), "{error}");
}

// spec: SBR-3, SBR-7
#[test]
fn refuses_a_document_that_is_not_cyclonedx() {
    let spdx = json!({ "spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT" });
    let error = refused(spdx.to_string().as_bytes());
    assert_eq!(error, ReadError::NotCycloneDx(None));
    assert!(
        error.to_string().starts_with("not a CycloneDX SBOM"),
        "{error}"
    );

    let other = json!({ "bomFormat": "SomethingElse", "specVersion": "1.6" });
    let error = refused(other.to_string().as_bytes());
    assert_eq!(
        error,
        ReadError::NotCycloneDx(Some("\"SomethingElse\"".into()))
    );
    assert!(error.to_string().contains("SomethingElse"), "{error}");

    let error = refused(b"[]");
    assert_eq!(error, ReadError::NotCycloneDx(None));
}

// spec: SBR-3, SBR-7
#[test]
fn refuses_a_document_with_no_spec_version() {
    for document in [
        json!({ "bomFormat": "CycloneDX", "version": 1 }),
        json!({ "bomFormat": "CycloneDX", "specVersion": 1.6 }),
    ] {
        let error = refused(document.to_string().as_bytes());
        assert_eq!(error, ReadError::MissingSpecVersion, "{document}");
        assert_eq!(error.to_string(), "missing spec version");
    }
}

// spec: SBR-3, SBR-7
#[test]
fn refuses_an_unsupported_spec_version_quoting_it() {
    for text in ["1.2", "1.0", "2.0", "1.6.1", ""] {
        let error = refused(bom(text, &json!([])).to_string().as_bytes());
        assert_eq!(error, ReadError::UnsupportedSpecVersion(text.into()));
        assert!(
            error.to_string().starts_with("unsupported spec version"),
            "{error}"
        );
        assert!(
            error.to_string().contains(&format!("\"{text}\"")),
            "{error}"
        );
        assert!(
            error.to_string().ends_with("1.3 to 1.7 are read"),
            "{error}"
        );
    }
}

// spec: SBR-3, SBR-7
#[test]
fn refuses_a_document_that_does_not_match_its_spec_version() {
    let error = refused(bom("1.6", &json!("not a list")).to_string().as_bytes());
    assert!(matches!(error, ReadError::Invalid(_)), "{error:?}");
    assert!(error.to_string().starts_with("invalid SBOM: "), "{error}");
}

// spec: SBR-7
#[test]
fn checks_the_format_before_the_spec_version() {
    let error = refused(json!({ "specVersion": "9.9" }).to_string().as_bytes());
    assert_eq!(error, ReadError::NotCycloneDx(None));
}

// spec: SBR-1
#[test]
fn reads_an_sbom_preceded_by_a_utf8_byte_order_mark() {
    let document = bom("1.6", &json!([{ "type": "library", "name": "serde" }]));
    let mut bytes = b"\xEF\xBB\xBF".to_vec();
    bytes.extend(document.to_string().into_bytes());
    let sbom = read_json(bytes.as_slice()).expect("readable");
    assert_eq!(sbom.components, vec![named("serde")]);
}

/// A reader that fails, as a directory or a broken pipe does.
struct FailingReader;

impl std::io::Read for FailingReader {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("disk on fire"))
    }
}

// spec: SBR-3, SBR-7
#[test]
fn reports_an_input_that_cannot_be_read() {
    let error = read_json(FailingReader).expect_err("refused");
    assert_eq!(error, ReadError::Io("disk on fire".into()));
    assert_eq!(error.to_string(), "cannot read the input: disk on fire");
}
