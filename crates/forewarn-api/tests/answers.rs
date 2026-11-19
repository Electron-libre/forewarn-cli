//! The answers of the service to an upload and to the account of a token, read from a status and a body, and written
//! back as the JSON they are read from (`specs/upload-api.md`).

use forewarn_api::{
    AccountAnswer, ErrorBody, ErrorCode, Receipt, UploadAnswer, Warning, WarningCode,
    read_account_answer, read_upload_answer, sbom_upload_path,
};

fn receipt_json(warnings: &str) -> String {
    format!(
        r#"{{"product": "acme-gateway", "version": "2.4.0", "spec_version": "1.6", "components": 3,
            "received_at": "2026-11-17T10:42:07.123456Z", "first_uploaded_at": "2026-11-17T10:42:07.123456Z",
            "warnings": {warnings}}}"#
    )
}

fn receipt(warnings: Vec<Warning>) -> Receipt {
    Receipt {
        product: "acme-gateway".to_owned(),
        version: "2.4.0".to_owned(),
        spec_version: "1.6".to_owned(),
        components: 3,
        received_at: "2026-11-17T10:42:07.123456Z".to_owned(),
        first_uploaded_at: "2026-11-17T10:42:07.123456Z".to_owned(),
        warnings,
    }
}

fn refused(status: u16, error: ErrorCode, message: Option<&str>) -> UploadAnswer {
    UploadAnswer::Refused {
        status,
        body: ErrorBody {
            error,
            message: message.map(str::to_owned),
        },
    }
}

// spec: UPA-H1
#[test]
fn the_cli_builds_the_route_and_reads_a_new_version_stored() {
    assert_eq!(
        sbom_upload_path("@acme/gateway", "2.4.0+build 7").as_deref(),
        Ok("/api/v1/products/%40acme%2Fgateway/versions/2.4.0%2Bbuild%207/sbom")
    );
    assert_eq!(
        read_upload_answer(201, receipt_json("[]").as_bytes()),
        Ok(UploadAnswer::Created(receipt(vec![])))
    );
}

// spec: UPA-3, UPA-7
#[test]
fn a_new_version_and_a_replaced_sbom_are_told_apart() {
    assert_eq!(
        read_upload_answer(200, receipt_json("[]").as_bytes()),
        Ok(UploadAnswer::Replaced(receipt(vec![])))
    );
}

// spec: UPA-7, UPA-9
#[test]
fn a_receipt_carries_its_warnings() {
    let body = receipt_json(
        r#"[{"code": "spec_version_below_minimum", "message": "CycloneDX 1.5 is older than 1.6"}]"#,
    );
    assert_eq!(
        read_upload_answer(200, body.as_bytes()),
        Ok(UploadAnswer::Replaced(receipt(vec![Warning {
            code: WarningCode::SpecVersionBelowMinimum,
            message: "CycloneDX 1.5 is older than 1.6".to_owned(),
        }])))
    );
}

// spec: UPA-H2
#[test]
fn the_cli_reads_a_refused_upload_with_its_code_and_message() {
    assert_eq!(
        read_upload_answer(
            422,
            br#"{"error": "unreadable_sbom", "message": "not CycloneDX"}"#
        ),
        Ok(refused(
            422,
            ErrorCode::UnreadableSbom,
            Some("not CycloneDX")
        ))
    );
}

// spec: UPA-3, UPA-8
#[test]
fn a_refusal_without_a_message_is_read() {
    assert_eq!(
        read_upload_answer(401, br#"{"error": "unauthorized"}"#),
        Ok(refused(401, ErrorCode::Unauthorized, None))
    );
}

// spec: UPA-9
#[test]
fn each_error_code_of_the_contract_has_its_variant_and_its_status() {
    let codes = [
        ("invalid_name", ErrorCode::InvalidName, 400),
        ("unreadable_body", ErrorCode::UnreadableBody, 400),
        ("unauthorized", ErrorCode::Unauthorized, 401),
        ("too_large", ErrorCode::TooLarge, 413),
        ("unreadable_sbom", ErrorCode::UnreadableSbom, 422),
        ("invalid_component", ErrorCode::InvalidComponent, 422),
        ("unavailable", ErrorCode::Unavailable, 503),
    ];
    for (text, code, status) in codes {
        let body = format!(r#"{{"error": "{text}", "message": "cause"}}"#);
        assert_eq!(
            read_upload_answer(status, body.as_bytes()),
            Ok(refused(status, code.clone(), Some("cause"))),
            "{text}"
        );
        assert_eq!(code.status(), Some(status), "{text}");
        assert_eq!(code.as_str(), text);
    }
}

// spec: UPA-4
#[test]
fn an_unknown_error_code_is_kept_with_its_text() {
    assert_eq!(
        read_upload_answer(429, br#"{"error": "rate_limited", "message": "later"}"#),
        Ok(refused(
            429,
            ErrorCode::Unknown("rate_limited".to_owned()),
            Some("later")
        ))
    );
    assert_eq!(ErrorCode::Unknown("rate_limited".to_owned()).status(), None);
}

// spec: UPA-4
#[test]
fn an_unknown_warning_code_is_kept_with_its_text() {
    let body = receipt_json(r#"[{"code": "no_supplier", "message": "3 components"}]"#);
    assert_eq!(
        read_upload_answer(201, body.as_bytes()),
        Ok(UploadAnswer::Created(receipt(vec![Warning {
            code: WarningCode::Unknown("no_supplier".to_owned()),
            message: "3 components".to_owned(),
        }])))
    );
}

// spec: UPA-10
#[test]
fn a_body_that_is_not_the_object_of_its_status_fails_naming_the_status() {
    let cases: [(u16, &[u8]); 5] = [
        (502, b"<html>Bad Gateway</html>"),
        (201, br#"{"error": "unauthorized"}"#),
        (200, br#"{"product": "acme-gateway"}"#),
        (422, br#"{"message": "no code"}"#),
        (400, b""),
    ];
    for (status, body) in cases {
        let error = read_upload_answer(status, body).expect_err("the answer is unreadable");
        assert_eq!(error.status, status);
        assert!(
            error.to_string().starts_with(&format!(
                "the answer {status} of the service is unreadable: "
            )),
            "{error}"
        );
    }
}

// spec: UPA-11
#[test]
fn a_field_the_contract_does_not_name_is_ignored() {
    let body = receipt_json(r#"[], "stored_until": "2027-01-01""#);
    assert_eq!(
        read_upload_answer(201, body.as_bytes()),
        Ok(UploadAnswer::Created(receipt(vec![])))
    );
    assert_eq!(
        read_upload_answer(401, br#"{"error": "unauthorized", "trace": "x"}"#),
        Ok(refused(401, ErrorCode::Unauthorized, None))
    );
}

// spec: UPA-12
#[test]
fn the_account_of_a_token_is_read() {
    assert_eq!(forewarn_api::ACCOUNT_PATH, "/api/v1/account");
    assert_eq!(
        read_account_answer(200, br#"{"account": "acme"}"#),
        Ok(AccountAnswer::Account("acme".to_owned()))
    );
    assert_eq!(
        read_account_answer(401, br#"{"error": "unauthorized"}"#),
        Ok(AccountAnswer::Refused {
            status: 401,
            body: ErrorBody {
                error: ErrorCode::Unauthorized,
                message: None
            }
        })
    );
    assert_eq!(
        read_account_answer(200, br#"{"name": "acme"}"#)
            .expect_err("no account")
            .status,
        200
    );
}

// spec: UPA-13
#[test]
fn each_type_writes_the_json_it_reads() {
    let written = serde_json::to_value(receipt(vec![Warning {
        code: WarningCode::SpecVersionBelowMinimum,
        message: "older".to_owned(),
    }]))
    .expect("a receipt is written");
    let expected: serde_json::Value = serde_json::from_str(&receipt_json(
        r#"[{"code": "spec_version_below_minimum", "message": "older"}]"#,
    ))
    .expect("JSON");
    assert_eq!(written, expected);

    let refusal = ErrorBody {
        error: ErrorCode::Unknown("rate_limited".to_owned()),
        message: None,
    };
    assert_eq!(
        serde_json::to_string(&refusal).expect("written"),
        r#"{"error":"rate_limited"}"#
    );
    assert_eq!(
        serde_json::to_string(&ErrorBody {
            error: ErrorCode::TooLarge,
            message: Some("over 10 MiB".to_owned())
        })
        .expect("written"),
        r#"{"error":"too_large","message":"over 10 MiB"}"#
    );
    assert_eq!(
        serde_json::to_string(&forewarn_api::Account {
            account: "acme".to_owned()
        })
        .expect("written"),
        r#"{"account":"acme"}"#
    );
}
