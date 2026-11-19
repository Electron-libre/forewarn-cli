//! The endpoint and the token of an upload (`specs/sbom-upload.md`), checked before anything is sent.

use forewarn_upload::{Endpoint, EndpointProblem, Token};

fn refused(endpoint: &str) -> EndpointProblem {
    Endpoint::parse(endpoint)
        .expect_err(&format!("{endpoint} is refused"))
        .problem
}

// spec: UPL-2, UPL-6
#[test]
fn https_endpoints_and_loopback_http_endpoints_are_accepted() {
    for endpoint in [
        "https://example.com",
        "https://example.com/root/",
        "HTTPS://Example.com:8443/a/b",
        "http://localhost:8080",
        "http://LOCALHOST",
        "http://127.0.0.1",
        "http://127.0.0.2/forewarn",
        "http://[::1]:9000",
    ] {
        assert!(Endpoint::parse(endpoint).is_ok(), "{endpoint} is accepted");
    }
}

// spec: UPL-2, UPL-6
#[test]
fn plain_http_to_a_host_that_is_not_loopback_is_refused() {
    for endpoint in [
        "http://example.com",
        "http://10.0.0.1",
        "http://[::2]",
        "http://127.0.0.1.example.com",
        "http://localhost.example.com",
    ] {
        assert_eq!(refused(endpoint), EndpointProblem::PlainHttp, "{endpoint}");
    }
}

// spec: UPL-6
#[test]
fn an_endpoint_that_is_not_an_absolute_http_url_is_refused() {
    assert_eq!(refused("ftp://example.com"), EndpointProblem::Scheme);
    for endpoint in [
        "example.com",
        "",
        "https://",
        "https://exa mple.com",
        "/api",
    ] {
        assert_eq!(refused(endpoint), EndpointProblem::NotAnUrl, "{endpoint:?}");
    }
}

// spec: UPL-6
#[test]
fn an_endpoint_with_a_query_or_a_fragment_is_refused() {
    assert_eq!(refused("https://example.com/?a=1"), EndpointProblem::Query);
    assert_eq!(refused("https://example.com?"), EndpointProblem::Query);
    assert_eq!(refused("https://example.com/#x"), EndpointProblem::Fragment);
}

// spec: UPL-6, UPL-11
#[test]
fn an_endpoint_with_user_information_is_refused_and_named_without_it() {
    let error = Endpoint::parse("https://ci:fw_secret@example.com/root").expect_err("refused");
    assert_eq!(error.problem, EndpointProblem::UserInformation);
    assert_eq!(error.endpoint, "https://***@example.com/root");
    let text = format!("{error} {error:?}");
    assert!(!text.contains("fw_secret"), "{text}");
    assert!(text.contains("https://***@example.com/root"), "{text}");
}

// spec: UPL-11
#[test]
fn an_endpoint_is_named_as_given_without_a_trailing_slash() {
    let endpoint = Endpoint::parse("http://127.0.0.1:8080/").expect("accepted");
    assert_eq!(endpoint.to_string(), "http://127.0.0.1:8080");
    let endpoint = Endpoint::parse("https://example.com/root/").expect("accepted");
    assert_eq!(endpoint.as_str(), "https://example.com/root");
    let error = Endpoint::parse("http://example.com/").expect_err("refused");
    assert_eq!(error.endpoint, "http://example.com");
    assert!(error.to_string().contains("http://example.com"), "{error}");
}

// spec: UPL-7
#[test]
fn a_token_of_visible_ascii_is_accepted() {
    assert!(Token::new("fw_secret".to_owned()).is_ok());
    assert!(Token::new("!~azAZ09-._".to_owned()).is_ok());
}

// spec: UPL-7, UPL-4
#[test]
fn a_token_empty_or_holding_another_character_is_refused_naming_none_of_it() {
    for token in [
        "",
        "fw secret",
        "fw\nsecret",
        "fw\tsecret",
        "fwé_secret",
        "fw\u{7f}secret",
    ] {
        let error = Token::new(token.to_owned()).expect_err("refused");
        let text = format!("{error} {error:?}");
        assert!(!text.contains("fw"), "{text}");
        assert!(!text.contains("secret"), "{text}");
    }
}

// spec: UPL-4
#[test]
fn the_debug_form_of_a_token_holds_none_of_it() {
    let token = Token::new("fw_secret".to_owned()).expect("accepted");
    let text = format!("{token:?}");
    assert!(!text.contains("fw_secret"), "{text}");
}

// spec: UPL-6, UPL-11, UPL-4
#[test]
fn credentials_are_named_as_stars_however_the_endpoint_is_malformed() {
    for (endpoint, named) in [
        ("ci:fw_secret@example.com", "***@example.com"),
        ("https:/ci:fw_secret@example.com", "***@example.com"),
        (
            "https://ci:fw#secret@example.com",
            "https://***@example.com",
        ),
        (
            "https://ci:fw?secret@example.com",
            "https://***@example.com",
        ),
        (
            "https://ci:fw/secret@example.com/",
            "https://***@example.com",
        ),
    ] {
        let error = Endpoint::parse(endpoint).expect_err("refused");
        assert_eq!(
            error.problem,
            EndpointProblem::UserInformation,
            "{endpoint}"
        );
        assert_eq!(error.endpoint, named, "{endpoint}");
        let text = format!("{error} {error:?}");
        assert!(!text.contains("secret"), "{text}");
    }
}

// spec: UPL-6
#[test]
fn an_endpoint_whose_port_or_host_is_malformed_is_refused() {
    for endpoint in [
        "http://localhost:abc",
        "http://127.0.0.1:99999",
        "http://[::1]evil.com",
        "https://[not-an-address]",
    ] {
        assert_eq!(refused(endpoint), EndpointProblem::NotAnUrl, "{endpoint}");
    }
}

// spec: UPL-11
#[test]
fn a_refused_endpoint_is_named_with_its_control_characters_escaped() {
    let error = Endpoint::parse("ftp://x\n::error::forged").expect_err("refused");
    assert!(!error.to_string().contains('\n'), "{error}");
}
