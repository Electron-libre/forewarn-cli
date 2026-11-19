//! `forewarn upload` (`specs/cli-upload.md`): the endpoint and the token from the arguments and the environment, the
//! SBOM read with the CycloneDX adapter then sent as is with the upload adapter, and what the service stored reported.

use std::env;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;
use std::io::{self, Read};
use std::path::Path;
use std::process::ExitCode;

use clap::error::ErrorKind;
use forewarn_cyclonedx::{ReadError, read_json};
use forewarn_domain::sbom::Sbom;
use forewarn_upload::{Endpoint, Stored, Token, UploadError, check_upload, upload};

use crate::args::UploadArgs;
use crate::escape::{escaped, push_escaped};
use crate::{input_name, is_stdin, subcommand_usage_error, unreadable, write_report};

/// The environment variable of the endpoint, read when `--endpoint` is not given (CUP-7).
const ENDPOINT_VARIABLE: &str = "FOREWARN_ENDPOINT";
/// The environment variable of the bearer token (CUP-8).
const TOKEN_VARIABLE: &str = "FOREWARN_TOKEN";

/// The exit codes of CUP-9 a failed upload adds to those of `check` and `match`.
const UNREACHABLE: u8 = 8;
const CREDENTIALS_REFUSED: u8 = 9;
const REFUSED: u8 = 10;
const UNREADABLE_ANSWER: u8 = 11;

/// A product name or a version the SBOM does not give, nor its option (CUP-11).
const MISSING: u8 = 2;

/// Runs `forewarn upload`: the arguments checked first, then the SBOM read, then sent (CUP-10).
pub(crate) fn run(args: &UploadArgs) -> Result<ExitCode, u8> {
    let endpoint = endpoint(args.endpoint.as_deref(), env::var_os(ENDPOINT_VARIABLE));
    // A dry run reads no token (CUP-8).
    let token = (!args.dry_run).then(|| token(env::var_os(TOKEN_VARIABLE)));
    let bytes = read_bytes(&args.sbom)?;
    let sbom =
        read_json(bytes.as_slice()).map_err(|error| unreadable(input_name(&args.sbom), &error))?;
    let (product, version) = names(args, &sbom)?;
    let report = if let Some(token) = token {
        let stored = upload(&endpoint, &token, &product, &version, &bytes)
            .map_err(|error| failed(&error))?;
        report(&endpoint, &product, &version, &stored)
    } else {
        check_upload(&product, &version, &bytes).map_err(|error| failed(&error))?;
        dry_run(&endpoint, &product, &version, bytes.len())
    };
    write_report(&report)?;
    Ok(ExitCode::SUCCESS)
}

/// Prints the line of a failed upload and returns its exit code (CUP-9, CUP-11).
fn failed(error: &UploadError) -> u8 {
    eprintln!("error: {}", escaped(&error.to_string()));
    exit_code(error)
}

/// The endpoint of `--endpoint`, else of the environment when set and not empty (CUP-7); exits with 2 when there is
/// none or the adapter refuses it (CUP-9).
fn endpoint(option: Option<&str>, variable: Option<OsString>) -> Endpoint {
    let variable = variable.filter(|value| !value.is_empty());
    let given = match (option, &variable) {
        (Some(option), _) => option.to_owned(),
        (None, Some(value)) => value.to_string_lossy().into_owned(),
        (None, None) => usage_error(
            ErrorKind::MissingRequiredArgument,
            &format!("give the endpoint of the service with --endpoint or {ENDPOINT_VARIABLE}"),
        ),
    };
    Endpoint::parse(&given)
        .unwrap_or_else(|error| usage_error(ErrorKind::InvalidValue, &escaped(&error.to_string())))
}

/// The token of the environment (CUP-8); exits with 2 when it is not set or the adapter refuses it (CUP-9), naming no
/// character of it.
fn token(variable: Option<OsString>) -> Token {
    let Some(variable) = variable else {
        usage_error(
            ErrorKind::MissingRequiredArgument,
            &format!("set {TOKEN_VARIABLE} to the token of the service"),
        )
    };
    // A token that is not UTF-8 holds a character the adapter refuses: its replacement character.
    Token::new(variable.to_string_lossy().into_owned()).unwrap_or_else(|error| {
        usage_error(
            ErrorKind::InvalidValue,
            &format!("{TOKEN_VARIABLE}: {error}"),
        )
    })
}

fn usage_error(kind: ErrorKind, message: &str) -> ! {
    subcommand_usage_error("upload", kind, message)
}

/// The bytes of the SBOM, read whole so that they are sent as read (CUP-1, CUP-4).
fn read_bytes(path: &Path) -> Result<Vec<u8>, u8> {
    let read = if is_stdin(path) {
        let mut bytes = Vec::new();
        io::stdin().lock().read_to_end(&mut bytes).map(|_| bytes)
    } else {
        fs::read(path)
    };
    read.map_err(|error| unreadable(input_name(path), &ReadError::Io(error.to_string())))
}

/// The product name and the version of the upload: those of the options, else of the SBOM's product (CUP-1, CUP-3);
/// prints the option to give and returns 2 when neither gives one (CUP-11).
fn names(args: &UploadArgs, sbom: &Sbom) -> Result<(String, String), u8> {
    let product = sbom.product.as_ref();
    let missing = |what: &str, option: &str| {
        eprintln!("error: the SBOM gives no {what} in metadata.component: give it with {option}");
        MISSING
    };
    let name = args
        .product
        .clone()
        .or_else(|| product.map(|product| product.name.clone()))
        .ok_or_else(|| missing("product", "--product"))?;
    let version = args
        .product_version
        .clone()
        .or_else(|| product.and_then(|product| product.version.clone()))
        .ok_or_else(|| missing("product version", "--product-version"))?;
    Ok((name, version))
}

/// The exit code of a failed upload (CUP-9).
fn exit_code(error: &UploadError) -> u8 {
    match error {
        UploadError::Unreachable { .. } => UNREACHABLE,
        UploadError::CredentialsRefused { .. } => CREDENTIALS_REFUSED,
        UploadError::UnreadableAnswer { .. } => UNREADABLE_ANSWER,
        // A name or a size refused before anything is sent, a refusal of the service, and a failure a later version
        // of the adapter may add.
        _ => REFUSED,
    }
}

/// The human report of a stored SBOM (CUP-12), each value of the SBOM and of the service escaped (CUP-13).
fn report(endpoint: &Endpoint, product: &str, version: &str, stored: &Stored) -> String {
    let (receipt, what) = match stored {
        Stored::Created(receipt) => (receipt, "a new version"),
        Stored::Replaced(receipt) => (receipt, "replaced the SBOM of a known version"),
    };
    let mut text = String::from("Uploaded ");
    push_escaped(&mut text, product);
    text.push(' ');
    push_escaped(&mut text, version);
    text.push_str(" to ");
    push_escaped(&mut text, endpoint.as_str());
    let _ = write!(
        text,
        "\nStored: {what}, {} components (CycloneDX ",
        receipt.components
    );
    push_escaped(&mut text, &receipt.spec_version);
    text.push_str("), received at ");
    push_escaped(&mut text, &receipt.received_at);
    text.push('\n');
    for warning in &receipt.warnings {
        text.push_str("Warning ");
        push_escaped(&mut text, warning.code.as_str());
        text.push_str(": ");
        push_escaped(&mut text, &warning.message);
        text.push('\n');
    }
    text
}

/// The report of a dry run: what would be sent, and that nothing was (CUP-5).
fn dry_run(endpoint: &Endpoint, product: &str, version: &str, size: usize) -> String {
    let mut text = String::from("Would upload ");
    push_escaped(&mut text, product);
    text.push(' ');
    push_escaped(&mut text, version);
    text.push_str(" to ");
    push_escaped(&mut text, endpoint.as_str());
    let _ = writeln!(text, ": an SBOM of {size} bytes; nothing sent (--dry-run)");
    text
}
