//! The OSV adapter of `forewarn`: reads vulnerability records in the OSV JSON format into the types of the domain
//! (`specs/osv-reading.md`). The `serde` model of the record stays in this crate (ADR 0003).

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use forewarn_domain::vulnerability::{AffectedPackage, Event, Range, RangeKind, Vulnerability};
use serde::Deserialize;
use serde_json::Value;

/// A file or a directory that could not be read, and why (`specs/osv-reading.md`, OSR-9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadError {
    /// The file or the directory at fault.
    pub path: PathBuf,
    pub cause: Cause,
}

/// Why a record cannot be read, the first that applies in the order of the variants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cause {
    /// The file or the directory cannot be read; the system's reason.
    Io(String),
    /// The file is not JSON; the parser's reason.
    NotJson(String),
    /// `schema_version` names a major version other than 1.
    UnsupportedSchemaVersion(String),
    /// The record does not have the shape of an OSV record; the parser's reason.
    Invalid(String),
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: ", self.path.display())?;
        match &self.cause {
            Cause::Io(reason) => write!(f, "cannot read the input: {reason}"),
            Cause::NotJson(reason) => write!(f, "not JSON: {reason}"),
            Cause::UnsupportedSchemaVersion(version) => write!(
                f,
                "unsupported schema version {version:?}: only OSV schema 1.x is read"
            ),
            Cause::Invalid(reason) => write!(f, "invalid OSV record: {reason}"),
        }
    }
}

impl std::error::Error for ReadError {}

/// Reads the OSV record of a file into a vulnerability.
///
/// # Errors
///
/// A [`ReadError`] naming the file and the first [`Cause`] that applies.
pub fn read_record(path: &Path) -> Result<Vulnerability, ReadError> {
    let error = |cause| ReadError {
        path: path.to_path_buf(),
        cause,
    };
    let bytes = fs::read(path).map_err(|e| error(Cause::Io(e.to_string())))?;
    let document: Value =
        serde_json::from_slice(&bytes).map_err(|e| error(Cause::NotJson(e.to_string())))?;
    if let Some(Value::String(version)) = document.get("schema_version")
        && version.split('.').next() != Some("1")
    {
        return Err(error(Cause::UnsupportedSchemaVersion(version.clone())));
    }
    let record: Record =
        serde_json::from_value(document).map_err(|e| error(Cause::Invalid(e.to_string())))?;
    Ok(record.into())
}

/// The fields of an OSV record the domain reads; every other field is ignored.
#[derive(Deserialize)]
struct Record {
    id: String,
    #[expect(
        dead_code,
        reason = "read for its type only: its major is checked on the JSON value"
    )]
    schema_version: Option<String>,
    aliases: Option<Vec<String>>,
    withdrawn: Option<Value>,
    affected: Option<Vec<Affected>>,
}

#[derive(Deserialize)]
struct Affected {
    package: Option<Package>,
    versions: Option<Vec<String>>,
    ranges: Option<Vec<OsvRange>>,
}

#[derive(Deserialize)]
struct Package {
    ecosystem: String,
    name: String,
}

#[derive(Deserialize)]
struct OsvRange {
    #[serde(rename = "type")]
    kind: OsvRangeKind,
    events: Option<Vec<OsvEvent>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum OsvRangeKind {
    Semver,
    Ecosystem,
    Git,
}

/// An event holds one of these keys; `limit` is read only to be ignored.
#[derive(Deserialize)]
struct OsvEvent {
    introduced: Option<String>,
    fixed: Option<String>,
    last_affected: Option<String>,
    #[expect(
        dead_code,
        reason = "read for its type only: a `limit` event is skipped"
    )]
    limit: Option<String>,
}

impl From<Record> for Vulnerability {
    fn from(record: Record) -> Self {
        let source = record
            .id
            .split_once('-')
            .map_or(record.id.as_str(), |(prefix, _)| prefix)
            .to_owned();
        Self {
            source,
            aliases: record.aliases.unwrap_or_default(),
            withdrawn: record.withdrawn.is_some(),
            affected: record
                .affected
                .unwrap_or_default()
                .into_iter()
                .filter_map(affected_package)
                .collect(),
            id: record.id,
        }
    }
}

fn affected_package(affected: Affected) -> Option<AffectedPackage> {
    let package = affected.package?;
    Some(AffectedPackage {
        ecosystem: package.ecosystem,
        name: package.name,
        versions: affected.versions.unwrap_or_default(),
        ranges: affected
            .ranges
            .unwrap_or_default()
            .into_iter()
            .map(range)
            .collect(),
    })
}

fn range(range: OsvRange) -> Range {
    let kind = match range.kind {
        OsvRangeKind::Semver => RangeKind::Semver,
        OsvRangeKind::Ecosystem => RangeKind::Ecosystem,
        OsvRangeKind::Git => RangeKind::Git,
    };
    let events = range
        .events
        .unwrap_or_default()
        .into_iter()
        .flat_map(|event| {
            [
                event.introduced.map(Event::Introduced),
                event.fixed.map(Event::Fixed),
                event.last_affected.map(Event::LastAffected),
            ]
        })
        .flatten()
        .collect();
    Range { kind, events }
}
