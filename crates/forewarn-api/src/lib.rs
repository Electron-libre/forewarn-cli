//! The API contract of an SBOM upload to a Forewarn service (ADR 0017, `specs/upload-api.md`): plain types and pure
//! functions, no I/O, shared by the upload adapter of the CLI and by the service.
//!
//! An upload is a `PUT` of the SBOM file as is to [`sbom_upload_path`], relative to the root of the service; its
//! answer is read with [`read_upload_answer`].

use std::fmt;

mod answer;

pub use answer::{
    Account, AccountAnswer, ErrorBody, ErrorCode, Receipt, Refusal, UnreadableAnswer, UploadAnswer,
    Warning, WarningCode, read_account_answer, read_upload_answer,
};

/// The path of the contract version every route lives under, as a literal for `concat!`.
macro_rules! api_root {
    () => {
        "/api/v1"
    };
}

/// The path of the contract version every route lives under (UPA-1).
pub const API_ROOT: &str = api_root!();

/// The route of the account of a token, relative to the root of the service (UPA-12).
pub const ACCOUNT_PATH: &str = concat!(api_root!(), "/account");

/// The most bytes of an SBOM the service stores: over it, it answers `413` `too_large` (UPA-9).
pub const MAX_SBOM_BYTES: u64 = 10 * 1024 * 1024;

/// The most characters (Unicode scalar values) a product name or a version may hold (UPA-6).
pub const MAX_NAME_CHARS: usize = 255;

/// The route of the SBOM of `version` of `product`, relative to the root of the service (UPA-1, UPA-5).
///
/// # Errors
/// [`InvalidName`] for a product name, then a version, the service would refuse or a URL client would resolve
/// (UPA-2, UPA-6).
pub fn sbom_upload_path(product: &str, version: &str) -> Result<String, InvalidName> {
    check(Name::Product, product)?;
    check(Name::Version, version)?;
    Ok(format!(
        "{API_ROOT}/products/{}/versions/{}/sbom",
        percent_encode(product),
        percent_encode(version)
    ))
}

/// Which name of an upload is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Name {
    Product,
    Version,
}

/// Why a name of an upload is refused (UPA-6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum NameProblem {
    /// Empty or only white space.
    Blank,
    /// Over [`MAX_NAME_CHARS`] characters.
    TooLong,
    /// Holds a control character.
    ControlCharacter,
    /// `.` or `..`, a segment a URL client would resolve.
    DotSegment,
}

/// A product name or a version refused before anything is sent (UPA-2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidName {
    pub name: Name,
    pub problem: NameProblem,
}

impl fmt::Display for InvalidName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self.name {
            Name::Product => "the product name",
            Name::Version => "the version",
        };
        match self.problem {
            NameProblem::Blank => write!(f, "{name} is blank"),
            NameProblem::TooLong => {
                write!(f, "{name} is longer than {MAX_NAME_CHARS} characters")
            }
            NameProblem::ControlCharacter => write!(f, "{name} holds a control character"),
            NameProblem::DotSegment => {
                write!(f, "{name} is `.` or `..`, which a URL client would resolve")
            }
        }
    }
}

impl std::error::Error for InvalidName {}

fn check(name: Name, value: &str) -> Result<(), InvalidName> {
    let problem = if value.chars().all(char::is_whitespace) {
        NameProblem::Blank
    } else if value.chars().count() > MAX_NAME_CHARS {
        NameProblem::TooLong
    } else if value.chars().any(char::is_control) {
        NameProblem::ControlCharacter
    } else if value == "." || value == ".." {
        NameProblem::DotSegment
    } else {
        return Ok(());
    };
    Err(InvalidName { name, problem })
}

/// The hexadecimal digits of a percent-encoded byte, in capitals (UPA-5).
const HEX: &[u8; 16] = b"0123456789ABCDEF";

/// `value` as a path segment: every byte of its UTF-8 but the unreserved characters of RFC 3986 written `%XX`.
fn percent_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0F)]));
        }
    }
    encoded
}
