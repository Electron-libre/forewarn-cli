//! Reading the SBOMs that existing tools produced for the sample project of `fixtures/` (`specs/sbom-reading.md`).

use std::fs::File;
use std::path::Path;

use forewarn_cyclonedx::read_json;
use forewarn_domain::sbom::{Component, Hash, Product, Sbom, SpecVersion};

fn read_fixture(name: &str) -> Sbom {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    let file = File::open(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    read_json(file).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn sha256(value: &str) -> Hash {
    Hash {
        algorithm: "SHA-256".into(),
        value: value.into(),
    }
}

const ITOA_SHA256: &str = "3bd1574e617a9a6c1f8f8181bd7e841e1f20e4277607ef28945765188d6284d4";
const SEMVER_SHA256: &str = "8a7852d02fc848982e0c167ef163aaff9cd91dc640ba85e263cb1ce46fae51cd";

fn crate_component(name: &str, version: &str) -> Component {
    Component {
        name: name.into(),
        version: Some(version.into()),
        purl: Some(format!("pkg:cargo/{name}@{version}")),
        ..Component::default()
    }
}

// spec: SBR-4, SBR-H1
#[test]
fn reads_the_sbom_of_syft() {
    let sbom = read_fixture("syft.cdx.json");
    assert_eq!(sbom.spec_version, SpecVersion::new(1, 6));
    assert!(!sbom.spec_version.is_below_bsi_minimum());
    assert_eq!(
        sbom.components,
        vec![
            crate_component("itoa", "1.0.19"),
            Component {
                name: "rollcall-fixture-sample".into(),
                version: Some("0.1.0".into()),
                ..Component::default()
            },
            crate_component("semver", "1.0.28"),
            Component {
                name: "/Cargo.lock".into(),
                hashes: vec![
                    Hash {
                        algorithm: "SHA-1".into(),
                        value: "43d45de0b845043ea75b756bd69e738d36ae618b".into(),
                    },
                    sha256("00ac93a831c7f41ee43ecfc2d95fa9127c372e34f4861fac4adb0517cba3b883"),
                ],
                ..Component::default()
            },
        ]
    );
}

// spec: SBR-9, SBR-11, SBR-H3
#[test]
fn reads_the_product_of_the_sbom_of_syft() {
    let sbom = read_fixture("syft.cdx.json");
    let listed = sbom
        .components
        .iter()
        .filter(|c| c.name == "rollcall-fixture-sample")
        .count();
    assert_eq!(
        listed, 1,
        "syft also lists the product among the components"
    );
    assert_eq!(
        sbom.product,
        Some(Product {
            name: "rollcall-fixture-sample".into(),
            version: Some("0.1.0".into()),
            purl: None,
            manufacturer: None,
            supplier: None,
        })
    );
}

// spec: SBR-9
#[test]
fn reads_the_product_of_the_sboms_of_cargo_cyclonedx_and_cdxgen() {
    for (fixture, purl) in [
        (
            "cargo-cyclonedx.cdx.json",
            "pkg:cargo/rollcall-fixture-sample@0.1.0?download_url=file://.",
        ),
        ("cdxgen.cdx.json", "pkg:cargo/rollcall-fixture-sample@0.1.0"),
    ] {
        let product = read_fixture(fixture).product.expect(fixture);
        assert_eq!(product.name, "rollcall-fixture-sample", "{fixture}");
        assert_eq!(product.version.as_deref(), Some("0.1.0"), "{fixture}");
        assert_eq!(product.purl.as_deref(), Some(purl), "{fixture}");
    }
}

// spec: SBR-4, SBR-13
#[test]
fn reads_the_sbom_of_cargo_cyclonedx_without_the_target_nested_in_its_product() {
    let sbom = read_fixture("cargo-cyclonedx.cdx.json");
    assert_eq!(sbom.spec_version, SpecVersion::new(1, 6));
    let dependency = |name, version, hash: &str| Component {
        authors: vec!["David Tolnay".into()],
        licenses: vec!["MIT OR Apache-2.0".into()],
        hashes: vec![sha256(hash)],
        ..crate_component(name, version)
    };
    assert_eq!(
        sbom.components,
        vec![
            dependency("itoa", "1.0.19", ITOA_SHA256),
            dependency("semver", "1.0.28", SEMVER_SHA256),
        ]
    );
}

// spec: SBR-4
#[test]
fn reads_the_sbom_of_cdxgen() {
    let sbom = read_fixture("cdxgen.cdx.json");
    assert_eq!(sbom.spec_version, SpecVersion::new(1, 7));
    assert_eq!(
        sbom.components,
        vec![
            Component {
                hashes: vec![sha256(ITOA_SHA256)],
                ..crate_component("itoa", "1.0.19")
            },
            crate_component("rollcall-fixture-sample", "0.1.0"),
            Component {
                hashes: vec![sha256(SEMVER_SHA256)],
                ..crate_component("semver", "1.0.28")
            },
        ]
    );
}

fn maven_component(group: &str, name: &str, version: &str) -> Component {
    Component {
        name: name.into(),
        version: Some(version.into()),
        purl: Some(format!("pkg:maven/{group}/{name}@{version}?type=jar")),
        ..Component::default()
    }
}

// spec: SBR-4, SBR-H4
#[test]
fn reads_the_modules_cdxgen_nests_in_the_product_of_a_maven_project() {
    let sbom = read_fixture("cdxgen-maven.cdx.json");
    let apache = |c: Component| Component {
        licenses: vec!["Apache-2.0".into()],
        ..c
    };
    assert_eq!(
        sbom.components,
        vec![
            apache(maven_component("commons-io", "commons-io", "2.7")),
            apache(maven_component("commons-io", "commons-io", "2.6")),
            maven_component("org.example.forewarn", "mod-b", "1.0"),
            maven_component("org.example.forewarn", "mod-a", "1.0"),
        ]
    );
    assert_eq!(
        sbom.product.map(|p| p.purl),
        Some(Some(
            "pkg:maven/org.example.forewarn/parent@1.0?type=pom".into()
        ))
    );
}
