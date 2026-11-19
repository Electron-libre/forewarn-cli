//! The answers of the service, read from a status and a body (UPA-3, UPA-7, UPA-8, UPA-12) and written back as the
//! JSON they are read from (UPA-13). A field the contract does not name is ignored (UPA-11); an error or a warning
//! code it does not name is kept with its text (UPA-4).

use std::fmt;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// The answer of the service to an upload (UPA-3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UploadAnswer {
    /// `201`: the SBOM is stored for a version the service did not know.
    Created(Receipt),
    /// `200`: the SBOM replaced the one of a known version.
    Replaced(Receipt),
    /// Any other status: nothing is stored (UPA-8).
    Refused(Refusal),
}

/// A refusal of the service: its status and the body it gave (UPA-8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub status: u16,
    pub body: ErrorBody,
}

/// What the service stored of an upload (UPA-7).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    /// The product name, decoded.
    pub product: String,
    /// The version, decoded.
    pub version: String,
    /// The CycloneDX version the service read, such as `1.6`.
    pub spec_version: String,
    /// The number of components stored.
    pub components: u64,
    /// When this SBOM was received, RFC 3339 in UTC, as the service wrote it.
    pub received_at: String,
    /// When the version was first uploaded, RFC 3339 in UTC, as the service wrote it.
    pub first_uploaded_at: String,
    pub warnings: Vec<Warning>,
}

/// A warning of a stored upload (UPA-7).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Warning {
    pub code: WarningCode,
    pub message: String,
}

/// The code of a warning (UPA-9), or one the contract does not name, kept with its text (UPA-4). Two codes are equal
/// when they are written alike, an `Unknown` holding a named code included.
#[derive(Clone, Debug, Eq, Serialize, Deserialize)]
#[serde(from = "String", into = "String")]
#[non_exhaustive]
pub enum WarningCode {
    /// The CycloneDX version of the SBOM is older than 1.6, the minimum of BSI TR-03183-2.
    SpecVersionBelowMinimum,
    Unknown(String),
}

impl WarningCode {
    /// The code as the service writes it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::SpecVersionBelowMinimum => "spec_version_below_minimum",
            Self::Unknown(code) => code,
        }
    }
}

impl PartialEq for WarningCode {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl From<String> for WarningCode {
    fn from(code: String) -> Self {
        [Self::SpecVersionBelowMinimum]
            .into_iter()
            .find(|named| named.as_str() == code)
            .unwrap_or(Self::Unknown(code))
    }
}

impl From<WarningCode> for String {
    fn from(code: WarningCode) -> Self {
        code.as_str().to_owned()
    }
}

/// The body of a refusal, `{"error": <code>, "message": <text>}`, `message` optional (UPA-8).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: ErrorCode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// The code of a refusal (UPA-9), or one the contract does not name, kept with its text (UPA-4). Two codes are equal
/// when they are written alike, an `Unknown` holding a named code included.
#[derive(Clone, Debug, Eq, Serialize, Deserialize)]
#[serde(from = "String", into = "String")]
#[non_exhaustive]
pub enum ErrorCode {
    /// The product name or the version is refused.
    InvalidName,
    /// The body could not be received.
    UnreadableBody,
    /// No valid token.
    Unauthorized,
    /// The body is over 10 MiB (10,485,760 bytes).
    TooLarge,
    /// The body is not a CycloneDX JSON SBOM the service reads.
    UnreadableSbom,
    /// A component the service refuses.
    InvalidComponent,
    /// The service cannot store now; a retry is safe.
    Unavailable,
    Unknown(String),
}

/// The codes the contract names (UPA-9).
const NAMED_ERROR_CODES: [ErrorCode; 7] = [
    ErrorCode::InvalidName,
    ErrorCode::UnreadableBody,
    ErrorCode::Unauthorized,
    ErrorCode::TooLarge,
    ErrorCode::UnreadableSbom,
    ErrorCode::InvalidComponent,
    ErrorCode::Unavailable,
];

impl ErrorCode {
    /// The code as the service writes it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::InvalidName => "invalid_name",
            Self::UnreadableBody => "unreadable_body",
            Self::Unauthorized => "unauthorized",
            Self::TooLarge => "too_large",
            Self::UnreadableSbom => "unreadable_sbom",
            Self::InvalidComponent => "invalid_component",
            Self::Unavailable => "unavailable",
            Self::Unknown(code) => code,
        }
    }

    /// The status the service answers with this code; `None` for a code the contract does not name.
    #[must_use]
    pub fn status(&self) -> Option<u16> {
        match Self::from(self.as_str().to_owned()) {
            Self::InvalidName | Self::UnreadableBody => Some(400),
            Self::Unauthorized => Some(401),
            Self::TooLarge => Some(413),
            Self::UnreadableSbom | Self::InvalidComponent => Some(422),
            Self::Unavailable => Some(503),
            Self::Unknown(_) => None,
        }
    }
}

impl PartialEq for ErrorCode {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl From<String> for ErrorCode {
    fn from(code: String) -> Self {
        NAMED_ERROR_CODES
            .into_iter()
            .find(|named| named.as_str() == code)
            .unwrap_or(Self::Unknown(code))
    }
}

impl From<ErrorCode> for String {
    fn from(code: ErrorCode) -> Self {
        code.as_str().to_owned()
    }
}

/// The answer of the service to the account of a token (UPA-12).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AccountAnswer {
    /// `200`: the name of the account of the token.
    Account(String),
    /// Any other status (UPA-8).
    Refused(Refusal),
}

/// The body of the answer `200` to the account of a token (UPA-12).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    pub account: String,
}

/// An answer whose body is not the JSON object its status calls for (UPA-10).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnreadableAnswer {
    pub status: u16,
    pub reason: String,
}

impl fmt::Display for UnreadableAnswer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the answer {} of the service is unreadable: {}",
            self.status, self.reason
        )
    }
}

impl std::error::Error for UnreadableAnswer {}

/// Reads the answer of the service to an upload (UPA-3, UPA-7, UPA-8).
///
/// # Errors
/// [`UnreadableAnswer`] when the body is not the JSON object its status calls for (UPA-10).
pub fn read_upload_answer(status: u16, body: &[u8]) -> Result<UploadAnswer, UnreadableAnswer> {
    match status {
        201 => read(status, body).map(UploadAnswer::Created),
        200 => read(status, body).map(UploadAnswer::Replaced),
        _ => read(status, body).map(|body| UploadAnswer::Refused(Refusal { status, body })),
    }
}

/// Reads the answer of the service to the account of a token (UPA-12).
///
/// # Errors
/// [`UnreadableAnswer`] when the body is not the JSON object its status calls for (UPA-10).
pub fn read_account_answer(status: u16, body: &[u8]) -> Result<AccountAnswer, UnreadableAnswer> {
    if status == 200 {
        read::<Account>(status, body).map(|body| AccountAnswer::Account(body.account))
    } else {
        read(status, body).map(|body| AccountAnswer::Refused(Refusal { status, body }))
    }
}

/// The body as the JSON object `T`: an array is refused, which the derived readers of `serde` would take field by
/// field (UPA-10).
fn read<T: DeserializeOwned>(status: u16, body: &[u8]) -> Result<T, UnreadableAnswer> {
    let unreadable = |reason: String| UnreadableAnswer { status, reason };
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|error| unreadable(error.to_string()))?;
    if !value.is_object() {
        return Err(unreadable("not a JSON object".to_owned()));
    }
    serde_json::from_value(value).map_err(|error| unreadable(error.to_string()))
}
