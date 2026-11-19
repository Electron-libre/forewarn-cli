//! The route of an SBOM upload: the product and the version in its path, percent-encoded, the names the service
//! would refuse refused before anything is sent (`specs/upload-api.md`).

use forewarn_api::{InvalidName, Name, NameProblem, sbom_upload_path};

// spec: UPA-1
#[test]
fn the_route_names_the_product_and_the_version_under_the_contract_version() {
    assert_eq!(
        sbom_upload_path("acme-gateway", "2.4.0"),
        Ok("/api/v1/products/acme-gateway/versions/2.4.0/sbom".to_owned())
    );
}

// spec: UPA-5
#[test]
fn every_byte_but_the_unreserved_characters_is_percent_encoded_in_capitals() {
    assert_eq!(
        sbom_upload_path("@acme/gateway", "2.4.0+build 7"),
        Ok("/api/v1/products/%40acme%2Fgateway/versions/2.4.0%2Bbuild%207/sbom".to_owned())
    );
    assert_eq!(
        sbom_upload_path("AZaz09-._~", "é?#%"),
        Ok("/api/v1/products/AZaz09-._~/versions/%C3%A9%3F%23%25/sbom".to_owned())
    );
}

fn refused(product: &str, version: &str) -> InvalidName {
    sbom_upload_path(product, version).expect_err("the name is refused")
}

// spec: UPA-2, UPA-6
#[test]
fn a_blank_name_is_refused_naming_which_of_the_two() {
    for blank in ["", " ", "\t\u{a0}"] {
        assert_eq!(
            refused(blank, "1.0"),
            InvalidName {
                name: Name::Product,
                problem: NameProblem::Blank
            },
            "{blank:?}"
        );
        assert_eq!(
            refused("acme", blank),
            InvalidName {
                name: Name::Version,
                problem: NameProblem::Blank
            },
            "{blank:?}"
        );
    }
}

// spec: UPA-6
#[test]
fn a_name_of_255_characters_is_accepted_and_one_of_256_refused() {
    let longest = "é".repeat(255);
    assert!(sbom_upload_path(&longest, "1.0").is_ok());
    assert_eq!(
        refused(&format!("{longest}é"), "1.0"),
        InvalidName {
            name: Name::Product,
            problem: NameProblem::TooLong
        }
    );
}

// spec: UPA-6
#[test]
fn a_name_holding_a_control_character_is_refused() {
    for name in ["acme\n", "ac\u{0}me", "acme\u{7f}", "acme\u{85}"] {
        assert_eq!(
            refused("acme", name),
            InvalidName {
                name: Name::Version,
                problem: NameProblem::ControlCharacter
            },
            "{name:?}"
        );
    }
}

// spec: UPA-6
#[test]
fn a_dot_segment_is_refused_but_a_name_holding_dots_is_not() {
    for name in [".", ".."] {
        assert_eq!(
            refused(name, "1.0"),
            InvalidName {
                name: Name::Product,
                problem: NameProblem::DotSegment
            },
            "{name:?}"
        );
    }
    assert!(sbom_upload_path("...", "..1").is_ok());
}

// spec: UPA-2
#[test]
fn the_error_names_the_product_name_or_the_version() {
    assert_eq!(refused("acme", "").to_string(), "the version is blank");
    assert_eq!(
        refused(&"a".repeat(256), "1.0").to_string(),
        "the product name is longer than 255 characters"
    );
    assert_eq!(
        refused("acme\n", "1.0").to_string(),
        "the product name holds a control character"
    );
    assert_eq!(
        refused("..", "1.0").to_string(),
        "the product name is `.` or `..`, which a URL client would resolve"
    );
}
