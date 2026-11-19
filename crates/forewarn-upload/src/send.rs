//! The upload itself (UPL-1, UPL-5): one `PUT` of the SBOM as is, its answer read with the contract of `forewarn-api`
//! and mapped to a receipt or to the error a CI job reports (UPL-3, UPL-9).

use std::fmt;
use std::time::Duration;

use forewarn_api::{
    ErrorBody, ErrorCode, InvalidName, MAX_SBOM_BYTES, Receipt, Refusal, UploadAnswer,
    read_upload_answer, sbom_upload_path,
};

use crate::{Endpoint, Token};

/// The most bytes of an answer read (UPL-9).
const ANSWER_LIMIT: u64 = 1024 * 1024;

/// The content type of the body (UPL-5).
const CONTENT_TYPE: &str = "application/vnd.cyclonedx+json";

/// How long an upload waits to connect, to send the SBOM, for the answer, and for its body (ADR 0018).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const SEND_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(2 * 60);
const BODY_TIMEOUT: Duration = Duration::from_secs(60);

/// What the service stored (UPL-1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Stored {
    /// `201`: a version the service did not know.
    Created(Receipt),
    /// `200`: the SBOM replaced the one of a known version.
    Replaced(Receipt),
}

/// Why an upload failed (UPL-3, UPL-9). No error holds the token (UPL-4); the endpoint is named as
/// [`Endpoint::as_str`] gives it (UPL-11).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum UploadError {
    /// The product name or the version is one the contract refuses; nothing was sent (UPL-8).
    InvalidName(InvalidName),
    /// The SBOM is over [`MAX_SBOM_BYTES`]; nothing was sent (UPL-8).
    TooLarge { size: u64 },
    /// The service cannot be reached, or its answer was not received whole.
    Unreachable { endpoint: String, reason: String },
    /// The service refused the credentials: an answer `401` or `403`.
    CredentialsRefused { endpoint: String, refusal: Refusal },
    /// The service refused the upload with another status.
    Refused { endpoint: String, refusal: Refusal },
    /// The answer is not one the contract reads, or is over 1 MiB.
    UnreadableAnswer {
        endpoint: String,
        status: u16,
        reason: String,
    },
}

impl fmt::Display for UploadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidName(invalid) => write!(f, "cannot upload: {invalid}"),
            Self::TooLarge { size } => write!(
                f,
                "cannot upload: the SBOM holds {size} bytes, over the {MAX_SBOM_BYTES} the service stores"
            ),
            Self::Unreachable { endpoint, reason } => {
                write!(f, "cannot reach the service at {endpoint}: {reason}")
            }
            Self::CredentialsRefused { endpoint, refusal } => write!(
                f,
                "the service at {endpoint} refused the credentials: {}",
                Described(refusal)
            ),
            Self::Refused { endpoint, refusal } => write!(
                f,
                "the service at {endpoint} refused the upload: {}",
                Described(refusal)
            ),
            Self::UnreadableAnswer {
                endpoint,
                status,
                reason,
            } => write!(
                f,
                "the answer {status} of the service at {endpoint} is unreadable: {reason}"
            ),
        }
    }
}

impl std::error::Error for UploadError {}

/// A refusal as an error line writes it: its status, its code and its message.
struct Described<'a>(&'a Refusal);

impl fmt::Display for Described<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Refusal { status, body } = self.0;
        write!(f, "{status} {}", body.error.as_str())?;
        match &body.message {
            Some(message) => write!(f, " ({message})"),
            None => Ok(()),
        }
    }
}

/// Uploads the SBOM of `version` of `product` to the service at `endpoint` with `token` (UPL-1, UPL-5): one `PUT`,
/// no retry, no redirect followed (UPL-10).
///
/// # Errors
/// [`UploadError`]: a name or a size refused before anything is sent (UPL-8), the service unreachable, the
/// credentials or the upload refused, an answer that cannot be read (UPL-9).
pub fn upload(
    endpoint: &Endpoint,
    token: &Token,
    product: &str,
    version: &str,
    sbom: &[u8],
) -> Result<Stored, UploadError> {
    let path = checked(product, version, sbom)?;
    let named = || endpoint.as_str().to_owned();
    let unreachable = |error: &ureq::Error| UploadError::Unreachable {
        endpoint: named(),
        reason: token.redact(&error.to_string()),
    };
    let response = agent(endpoint)
        .put(format!("{endpoint}{path}"))
        .header("Authorization", format!("Bearer {}", token.expose()))
        .header("Content-Type", CONTENT_TYPE)
        .send(sbom)
        .map_err(|error| unreachable(&error))?;
    let status = response.status().as_u16();
    let unreadable = |reason: &str| UploadError::UnreadableAnswer {
        endpoint: named(),
        status,
        reason: token.redact(reason),
    };
    let body = match response
        .into_body()
        .with_config()
        .limit(ANSWER_LIMIT)
        .read_to_vec()
    {
        Ok(body) => body,
        Err(ureq::Error::BodyExceedsLimit(_)) => {
            return Err(unreadable("the answer is over 1 MiB"));
        }
        Err(error) => return Err(unreachable(&error)),
    };
    match read_upload_answer(status, &body) {
        Ok(UploadAnswer::Created(receipt)) => Ok(Stored::Created(receipt)),
        Ok(UploadAnswer::Replaced(receipt)) => Ok(Stored::Replaced(receipt)),
        Ok(UploadAnswer::Refused(refusal)) => {
            let refusal = redacted(refusal, token);
            Err(if matches!(refusal.status, 401 | 403) {
                UploadError::CredentialsRefused {
                    endpoint: named(),
                    refusal,
                }
            } else {
                UploadError::Refused {
                    endpoint: named(),
                    refusal,
                }
            })
        }
        Err(error) => Err(unreadable(&error.reason)),
    }
}

/// Checks an upload as [`upload`] does before anything is sent (UPL-8), for a caller that sends nothing.
///
/// # Errors
/// [`UploadError::InvalidName`] for a product name or a version the contract refuses, [`UploadError::TooLarge`] for
/// an SBOM over [`MAX_SBOM_BYTES`].
pub fn check_upload(product: &str, version: &str, sbom: &[u8]) -> Result<(), UploadError> {
    checked(product, version, sbom).map(|_| ())
}

/// The route of the upload, once its names and its size are checked (UPL-8).
fn checked(product: &str, version: &str, sbom: &[u8]) -> Result<String, UploadError> {
    let path = sbom_upload_path(product, version).map_err(UploadError::InvalidName)?;
    let size = u64::try_from(sbom.len()).unwrap_or(u64::MAX);
    if size > MAX_SBOM_BYTES {
        return Err(UploadError::TooLarge { size });
    }
    Ok(path)
}

/// The refusal with each occurrence of the token in its code and its message written `***` (UPL-12).
fn redacted(refusal: Refusal, token: &Token) -> Refusal {
    let Refusal { status, body } = refusal;
    Refusal {
        status,
        body: ErrorBody {
            error: ErrorCode::from(token.redact(body.error.as_str())),
            message: body.message.map(|message| token.redact(&message)),
        },
    }
}

/// The agent of an upload: no redirect followed (UPL-10), no proxy to a loopback endpoint in plain HTTP (UPL-13),
/// every status read as an answer, the timeouts of ADR 0018.
fn agent(endpoint: &Endpoint) -> ureq::Agent {
    let builder = ureq::Agent::config_builder();
    let builder = if endpoint.is_plain_http() {
        builder.proxy(None)
    } else {
        builder
    };
    builder
        .http_status_as_error(false)
        .max_redirects(0)
        .timeout_connect(Some(CONNECT_TIMEOUT))
        .timeout_send_body(Some(SEND_TIMEOUT))
        .timeout_recv_response(Some(RESPONSE_TIMEOUT))
        .timeout_recv_body(Some(BODY_TIMEOUT))
        .build()
        .into()
}
