//! The OSV adapter of `forewarn`: reads vulnerability records in the OSV JSON format into the types of the domain
//! (`specs/osv-reading.md`). The `serde` model of the record stays in this crate (ADR 0003). The module [`fetch`]
//! downloads the archive of each ecosystem into a cache (ADR 0004); the module [`api`] queries the OSV API, an opt-in
//! source (ADR 0006).

pub mod api;
pub mod fetch;

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
    /// The record does not have the shape of an OSV record, or its `id` is empty; the reason.
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
    parse_record(&bytes).map_err(error)
}

/// Reads the bytes of an OSV record into a vulnerability, or gives the first [`Cause`] that refuses them.
fn parse_record(bytes: &[u8]) -> Result<Vulnerability, Cause> {
    match serde_json::from_slice::<Record>(bytes) {
        Ok(record) => {
            check_schema_version(record.schema_version.as_ref())?;
            // An empty id would group unrelated records under one name (OSR-36).
            if record.id.trim_ascii().is_empty() {
                return Err(Cause::Invalid("`id` is empty".to_owned()));
            }
            Ok(record.into())
        }
        // A shape error: the schema version, when the document is JSON, is the cause that comes first.
        Err(shape) if shape.is_data() => {
            let document: Value =
                serde_json::from_slice(bytes).map_err(|e| Cause::NotJson(e.to_string()))?;
            check_schema_version(document.get("schema_version"))?;
            Err(Cause::Invalid(shape.to_string()))
        }
        Err(syntax) => Err(Cause::NotJson(syntax.to_string())),
    }
}

/// Whether a name can be a path segment of a URL and a file name as it is: not empty, not first `.`, only ASCII
/// letters, digits, `.`, `-`, `_` and the bytes of `extra` (OSR-17, OSR-31).
fn is_path_segment(name: &str, extra: &[u8]) -> bool {
    !name.is_empty()
        && !name.starts_with('.')
        && name.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_') || extra.contains(&b)
        })
}

/// Refuses a `schema_version` string whose major is not 1; any other value is not read.
fn check_schema_version(version: Option<&Value>) -> Result<(), Cause> {
    match version {
        Some(Value::String(version)) if version.split('.').next() != Some("1") => {
            Err(Cause::UnsupportedSchemaVersion(version.clone()))
        }
        _ => Ok(()),
    }
}

/// Reads the OSV records of a directory laid out as an OSV ecosystem archive: each file directly in it whose name
/// ends in `.json`, in the byte order of the file names; its subdirectories and its other files are ignored.
///
/// # Errors
///
/// A [`ReadError`] naming the directory when it cannot be listed, else the first file whose record cannot be read.
pub fn read_directory(path: &Path) -> Result<Vec<Vulnerability>, ReadError> {
    let io_error = |e: std::io::Error| ReadError {
        path: path.to_path_buf(),
        cause: Cause::Io(e.to_string()),
    };
    let mut files = Vec::new();
    for entry in fs::read_dir(path).map_err(io_error)? {
        let file = entry.map_err(io_error)?.path();
        let is_json = file
            .file_name()
            .is_some_and(|name| name.as_encoded_bytes().ends_with(b".json"));
        if !is_json {
            continue;
        }
        // Follows a link, so that a dangling one fails naming its file rather than being skipped.
        let metadata = fs::metadata(&file).map_err(|e| ReadError {
            path: file.clone(),
            cause: Cause::Io(e.to_string()),
        })?;
        if metadata.is_file() {
            files.push(file);
        }
    }
    // The files share one parent: ordering the paths orders their names.
    files.sort();
    files.iter().map(|file| read_record(file)).collect()
}

/// The fields of an OSV record the domain reads; every other field is ignored.
#[derive(Deserialize)]
struct Record {
    id: String,
    schema_version: Option<Value>,
    aliases: Option<Vec<String>>,
    withdrawn: Option<String>,
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

/// The domain events of an OSV event: none for a `limit` event, which the domain does not read.
#[derive(Deserialize)]
#[serde(try_from = "RawEvent")]
struct OsvEvent(Vec<Event>);

#[derive(Deserialize)]
struct RawEvent {
    introduced: Option<String>,
    fixed: Option<String>,
    last_affected: Option<String>,
    limit: Option<Value>,
}

impl TryFrom<RawEvent> for OsvEvent {
    type Error = &'static str;

    /// Refuses an event of no known kind: dropped, it could leave a range open to every later version.
    fn try_from(raw: RawEvent) -> Result<Self, Self::Error> {
        let events: Vec<Event> = [
            raw.introduced.map(Event::Introduced),
            raw.fixed.map(Event::Fixed),
            raw.last_affected.map(Event::LastAffected),
        ]
        .into_iter()
        .flatten()
        .collect();
        if events.is_empty() && raw.limit.is_none() {
            return Err(
                "an event holds none of `introduced`, `fixed`, `last_affected` and `limit`",
            );
        }
        Ok(Self(events))
    }
}

impl From<Record> for Vulnerability {
    /// Reads the id and each alias without the ASCII whitespace around them (OSR-34), an alias left empty dropped
    /// (OSR-35).
    fn from(record: Record) -> Self {
        let id = trimmed(record.id);
        let source = id
            .split_once('-')
            .map(|(prefix, _)| prefix)
            .filter(|prefix| !prefix.is_empty())
            .unwrap_or(&id)
            .to_owned();
        Self {
            source,
            aliases: record
                .aliases
                .unwrap_or_default()
                .into_iter()
                .map(trimmed)
                .filter(|alias| !alias.is_empty())
                .collect(),
            withdrawn: record.withdrawn.is_some(),
            affected: record
                .affected
                .unwrap_or_default()
                .into_iter()
                .filter_map(affected_package)
                .collect(),
            id,
        }
    }
}

/// The text without the ASCII whitespace around it, reusing it when there is none.
fn trimmed(text: String) -> String {
    if text.trim_ascii().len() == text.len() {
        text
    } else {
        text.trim_ascii().to_owned()
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
        .flat_map(|OsvEvent(events)| events)
        .collect();
    Range { kind, events }
}
