//! Reading a CycloneDX JSON SBOM into the domain (`specs/sbom-reading.md`).

use forewarn_cyclonedx::{ReadError, read_json};
use forewarn_domain::sbom::{Component, Hash, Product, Sbom, SpecVersion};
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
            "bom-ref": "serde-ref",
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
                bom_ref: Some("serde-ref".into()),
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
                first_party: false,
                file: false,
                source: None,
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
fn identifies_an_organization_with_no_name_by_its_contact_email_then_its_url() {
    let contact = json!([{ "name": "Jane Doe", "phone": "+33 1 00 00 00 00" }, { "email": "sec@example.com" }]);
    let by_email = creators(&json!({
        "type": "library",
        "name": "a",
        "supplier": { "url": ["https://example.com"], "contact": contact },
        "manufacturer": { "name": "  ", "contact": [{ "email": "maker@example.com" }] },
    }));
    assert_eq!(by_email.supplier.as_deref(), Some("sec@example.com"));
    assert_eq!(by_email.manufacturer.as_deref(), Some("maker@example.com"));
    let by_url = creators(&json!({
        "type": "library",
        "name": "b",
        "supplier": { "url": ["  ", "https://example.com"], "contact": [{ "email": " " }] },
        "manufacturer": { "url": ["https://maker.example"] },
    }));
    assert_eq!(by_url.supplier.as_deref(), Some("https://example.com"));
    assert_eq!(
        by_url.manufacturer.as_deref(),
        Some("https://maker.example")
    );
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

// spec: SBR-15
#[test]
fn tells_a_file_component_by_its_type() {
    let document = bom(
        "1.6",
        &json!([
            { "type": "file", "name": "/pom.xml" },
            { "type": "library", "name": "lib" },
            { "type": "File", "name": "odd" },
            { "type": "application", "name": "app", "components": [
                { "type": "file", "name": "nested.txt" }
            ] }
        ]),
    );
    let sbom = read(&document).expect("readable");
    let files: Vec<(&str, bool)> = sbom
        .components
        .iter()
        .map(|c| (c.name.as_str(), c.file))
        .collect();
    assert_eq!(
        files,
        [
            ("/pom.xml", true),
            ("lib", false),
            ("odd", false),
            ("app", false),
            ("nested.txt", true)
        ]
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

fn with_metadata(spec_version: &str, metadata: &Value) -> Value {
    let mut document = bom(
        spec_version,
        &json!([{ "type": "library", "name": "serde" }]),
    );
    document["metadata"] = metadata.clone();
    document
}

fn product_of(spec_version: &str, metadata: &Value) -> Option<Product> {
    read(&with_metadata(spec_version, metadata))
        .expect("readable")
        .product
}

fn application(extra: &Value) -> Value {
    let mut component = json!({ "type": "application", "name": "shop", "version": "2.1.0" });
    for (key, value) in extra.as_object().expect("an object") {
        component[key] = value.clone();
    }
    component
}

// spec: SBR-9, SBR-12
#[test]
fn reads_the_product_the_sbom_describes() {
    let metadata = json!({
        "component": application(&json!({
            "purl": "pkg:generic/shop@2.1.0",
            "manufacturer": { "name": "Acme" },
        })),
        "supplier": { "name": "Acme Distribution" },
    });
    assert_eq!(
        product_of("1.6", &metadata),
        Some(Product {
            name: "shop".into(),
            version: Some("2.1.0".into()),
            purl: Some("pkg:generic/shop@2.1.0".into()),
            manufacturer: Some("Acme".into()),
            supplier: Some("Acme Distribution".into()),
        })
    );
}

// spec: SBR-9
#[test]
fn reads_no_product_without_a_metadata_component() {
    let sbom = read(&bom(
        "1.6",
        &json!([{ "type": "library", "name": "serde" }]),
    ))
    .expect("readable");
    assert_eq!(sbom.product, None);
    assert_eq!(sbom.components, vec![named("serde")]);
    let metadata = json!({ "timestamp": "2026-11-13T09:30:00Z" });
    assert_eq!(product_of("1.6", &metadata), None);
}

// spec: SBR-12
#[test]
fn takes_the_manufacturer_of_the_product_not_the_one_of_the_bom() {
    let component = application(&json!({ "manufacturer": { "name": "Acme" } }));
    let both = json!({ "component": component, "manufacturer": { "name": "SBOM Service" } });
    let only_bom =
        json!({ "component": application(&json!({})), "manufacturer": { "name": "SBOM Service" } });
    assert_eq!(
        product_of("1.6", &both).and_then(|p| p.manufacturer),
        Some("Acme".into())
    );
    assert_eq!(
        product_of("1.6", &only_bom).and_then(|p| p.manufacturer),
        None
    );
}

// spec: SBR-12
#[test]
fn takes_the_manufacturer_of_the_product_before_the_deprecated_manufacture() {
    let metadata = json!({
        "component": application(&json!({ "manufacturer": { "name": "Acme" } })),
        "manufacture": { "name": "Other" },
    });
    assert_eq!(
        product_of("1.6", &metadata).and_then(|p| p.manufacturer),
        Some("Acme".into())
    );
}

// spec: SBR-12
#[test]
fn takes_the_deprecated_manufacture_as_the_manufacturer() {
    let metadata =
        json!({ "component": application(&json!({})), "manufacture": { "name": "Acme" } });
    assert_eq!(
        product_of("1.5", &metadata).and_then(|p| p.manufacturer),
        Some("Acme".into())
    );
}

// spec: SBR-12
#[test]
fn takes_no_manufacturer_from_an_organization_without_a_name() {
    let manufacturer = json!({
        "name": "  ",
        "url": ["https://acme.example"],
        "contact": [{ "email": "security@acme.example" }],
    });
    let component = application(&json!({ "manufacturer": manufacturer }));
    let alone = json!({ "component": component });
    let with_manufacture = json!({ "component": component, "manufacture": { "name": "Acme" } });
    assert_eq!(product_of("1.6", &alone).and_then(|p| p.manufacturer), None);
    assert_eq!(
        product_of("1.6", &with_manufacture).and_then(|p| p.manufacturer),
        Some("Acme".into())
    );
}

// spec: SBR-12
#[test]
fn takes_the_supplier_of_the_product_when_that_of_the_metadata_has_no_name() {
    let metadata = json!({
        "component": application(&json!({ "supplier": { "name": "Acme" } })),
        "supplier": { "contact": [{ "email": "security@distribution.example" }] },
    });
    assert_eq!(
        product_of("1.6", &metadata).and_then(|p| p.supplier),
        Some("Acme".into())
    );
}

// spec: SBR-12
#[test]
fn takes_the_supplier_of_the_metadata_before_that_of_the_product() {
    let component = application(&json!({ "supplier": { "name": "Other" } }));
    let both = json!({ "component": component, "supplier": { "name": "Acme" } });
    let only_component = json!({ "component": component });
    assert_eq!(
        product_of("1.6", &both).and_then(|p| p.supplier),
        Some("Acme".into())
    );
    let product = product_of("1.6", &only_component).expect("a product");
    assert_eq!(product.supplier, Some("Other".into()));
    assert_eq!(product.manufacturer, None);
}

// spec: SBR-11
#[test]
fn adds_no_component_for_the_product() {
    let metadata = json!({ "component": application(&json!({})) });
    let sbom = read(&with_metadata("1.6", &metadata)).expect("readable");
    assert_eq!(sbom.components, vec![named("serde")]);
    assert_eq!(sbom.product.map(|p| p.name), Some("shop".into()));
}

/// An SBOM listing `top` whose product nests `nested`.
fn with_nested_product(top: &Value, nested: &Value) -> Sbom {
    let mut document = bom("1.6", top);
    document["metadata"] = json!({ "component": application(&json!({ "components": nested })) });
    read(&document).expect("readable")
}

// spec: SBR-13
#[test]
fn reads_the_components_nested_in_the_product_after_the_top_level_ones() {
    let sbom = with_nested_product(
        &json!([{ "type": "library", "name": "serde", "bom-ref": "serde" }]),
        &json!([
            { "type": "library", "name": "a", "bom-ref": "a", "components": [
                { "type": "library", "name": "a1", "bom-ref": "a1" }
            ] },
            { "type": "library", "name": "b" }
        ]),
    );
    assert_eq!(names(&sbom), ["serde", "a", "a1", "b"]);
}

// spec: SBR-13
#[test]
fn skips_a_component_nested_in_the_product_already_read_but_reads_its_own() {
    let sbom = with_nested_product(
        &json!([{ "type": "library", "name": "serde", "bom-ref": "serde" }]),
        &json!([
            { "type": "library", "name": "serde again", "bom-ref": "serde", "components": [
                { "type": "library", "name": "serde_derive", "bom-ref": "serde_derive" },
                { "type": "library", "name": "serde twice", "bom-ref": "serde" }
            ] }
        ]),
    );
    assert_eq!(names(&sbom), ["serde", "serde_derive"]);
}

// spec: SBR-13
#[test]
fn reads_each_component_nested_in_the_product_with_a_blank_bom_ref() {
    let sbom = with_nested_product(
        &json!([{ "type": "library", "name": "serde", "bom-ref": "" }]),
        &json!([
            { "type": "library", "name": "a", "bom-ref": "" },
            { "type": "library", "name": "b", "bom-ref": "  " },
            { "type": "library", "name": "c", "bom-ref": "  " }
        ]),
    );
    assert_eq!(names(&sbom), ["serde", "a", "b", "c"]);
}

// spec: SBR-13
#[test]
fn skips_a_target_of_the_product_nested_in_it_but_reads_its_own() {
    let mut document = bom("1.6", &json!([]));
    document["metadata"] = json!({ "component": application(&json!({
        "purl": "pkg:cargo/shop@2.1.0?download_url=file://.",
        "components": [
            { "type": "application", "name": "shop", "purl": "pkg:cargo/shop@2.1.0#src/main.rs", "components": [
                { "type": "library", "name": "inside" }
            ] },
            { "type": "library", "name": "shop-core", "purl": "pkg:cargo/shop-core@2.1.0" },
            { "type": "library", "name": "other shop", "purl": "pkg:cargo/shop@2.0.0" }
        ]
    })) });
    let sbom = read(&document).expect("readable");
    assert_eq!(names(&sbom), ["inside", "shop-core", "other shop"]);
}

/// The names of the first-party components of `sbom`.
fn first_party(sbom: &Sbom) -> Vec<&str> {
    sbom.components
        .iter()
        .filter(|c| c.first_party)
        .map(|c| c.name.as_str())
        .collect()
}

// spec: SBR-14
#[test]
fn flags_first_party_a_component_with_the_package_url_of_the_product() {
    let mut document = bom(
        "1.6",
        &json!([
            { "type": "library", "name": "app jar", "purl": "pkg:maven/acme/app@1.0?type=jar" },
            { "type": "library", "name": "app 2", "purl": "pkg:maven/acme/app@2.0" },
            { "type": "library", "name": "lib", "purl": "pkg:maven/acme/lib@1.0" },
            { "type": "library", "name": "no purl" }
        ]),
    );
    document["metadata"] = json!({ "component": application(&json!({
        "purl": "pkg:maven/acme/app@1.0?type=pom"
    })) });
    let sbom = read(&document).expect("readable");
    assert_eq!(first_party(&sbom), ["app jar"]);
}

// spec: SBR-14
#[test]
fn flags_first_party_the_components_nested_in_the_product_of_its_type_and_namespace() {
    let mut document = bom(
        "1.6",
        &json!([{ "type": "library", "name": "dependency", "bom-ref": "dep", "purl": "pkg:maven/org.acme/dep@1.0" }]),
    );
    document["metadata"] = json!({ "component": application(&json!({
        "purl": "pkg:maven/org.acme/app@1.0?type=pom",
        "components": [
            { "type": "library", "name": "dependency again", "bom-ref": "dep" },
            { "type": "library", "name": "mod-a", "purl": "pkg:maven/org.acme/mod-a@1.0?type=jar", "components": [
                { "type": "library", "name": "log4j-core", "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" },
                { "type": "library", "name": "acme npm", "purl": "pkg:npm/org.acme/mod-b@1.0" }
            ] },
            { "type": "library", "name": "no purl" }
        ]
    })) });
    let sbom = read(&document).expect("readable");
    assert_eq!(
        names(&sbom),
        ["dependency", "mod-a", "log4j-core", "acme npm", "no purl"]
    );
    assert_eq!(first_party(&sbom), ["mod-a"]);
}

// spec: SBR-14
#[test]
fn flags_no_component_first_party_for_a_product_without_a_valid_package_url() {
    for purl in [None, Some(""), Some("  "), Some("not a purl")] {
        let mut product = json!({ "components": [
            { "type": "library", "name": "nested", "purl": "pkg:cargo/nested@1.0" },
            { "type": "library", "name": "blank", "purl": "" }
        ] });
        if let Some(purl) = purl {
            product["purl"] = json!(purl);
        }
        let mut document = bom(
            "1.6",
            &json!([{ "type": "library", "name": "top blank", "purl": purl.unwrap_or("") }]),
        );
        document["metadata"] = json!({ "component": application(&product) });
        let sbom = read(&document).expect("readable");
        assert_eq!(first_party(&sbom), Vec::<&str>::new(), "{purl:?}");
    }
}

// spec: SBR-14
#[test]
fn compares_the_package_urls_by_the_specification() {
    let mut document = bom(
        "1.6",
        &json!([
            { "type": "library", "name": "encoded", "purl": " pkg:NPM/@acme/app@1.0#dist " },
            { "type": "library", "name": "other", "purl": "pkg:npm/%40acme/lib@1.0" }
        ]),
    );
    document["metadata"] =
        json!({ "component": application(&json!({ "purl": "pkg:npm/%40acme/app@1.0" })) });
    let sbom = read(&document).expect("readable");
    assert_eq!(first_party(&sbom), ["encoded"]);
}
