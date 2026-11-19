//! The file of `forewarn match --awareness <file>`: the moment of awareness of each actively exploited CVE of each
//! product, read before the SBOM and rewritten whole when a run records a CVE it did not hold
//! (`specs/cli-match-awareness.md`, AWR-7 to AWR-11, ADR 0019).

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use forewarn_domain::date::Moment;
use forewarn_domain::deadlines::reporting_deadlines;
use serde_json::{Map, Value, json};

use crate::args::parse_moment;
use crate::drafts::replace;
use crate::error_line::{ErrorLine, path_and_cause};

/// The moments of awareness of a file, by product (`None` for an SBOM naming none) and CVE id.
pub struct AwarenessFile {
    path: PathBuf,
    moments: BTreeMap<(Option<String>, String), Moment>,
}

/// A file of moments that cannot be read (AWR-10) or written (AWR-11).
pub struct FileError {
    path: PathBuf,
    cause: Cause,
    write: bool,
}

enum Cause {
    Io(io::Error),
    NotJson(serde_json::Error),
    Invalid(String),
}

impl fmt::Display for Cause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => error.fmt(f),
            Self::NotJson(error) => write!(f, "not JSON: {error}"),
            Self::Invalid(why) => f.write_str(why),
        }
    }
}

impl ErrorLine for FileError {
    fn line(&self) -> String {
        let what = if self.write { "write" } else { "read" };
        format!(
            "cannot {what} the moments of awareness {}",
            path_and_cause(&self.path, &self.cause)
        )
    }
}

/// The product a file names: the name of the product of the SBOM without its leading and trailing white space,
/// `None` when the SBOM names none or a name made only of white space (AWR-7).
pub fn product_key(name: Option<&str>) -> Option<String> {
    name.map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
}

impl AwarenessFile {
    /// Reads the file of `path`, a path naming nothing, or lying under a file, holding no moment (AWR-8).
    ///
    /// # Errors
    /// [`FileError`] when the file cannot be read or is not as AWR-7 says (AWR-10).
    pub fn read(path: &Path) -> Result<Self, FileError> {
        let refused = |cause| FileError {
            path: path.to_owned(),
            cause,
            write: false,
        };
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                ) =>
            {
                return Ok(Self {
                    path: path.to_owned(),
                    moments: BTreeMap::new(),
                });
            }
            Err(error) => return Err(refused(Cause::Io(error))),
        };
        let document: Value =
            serde_json::from_slice(&bytes).map_err(|error| refused(Cause::NotJson(error)))?;
        let moments = parse(&document).map_err(|why| refused(Cause::Invalid(why)))?;
        Ok(Self {
            path: path.to_owned(),
            moments,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The moment the file records for `product` and `cve` (AWR-1).
    pub fn recorded(&self, product: Option<&str>, cve: &str) -> Option<Moment> {
        self.moments
            .get(&(product.map(str::to_owned), cve.to_owned()))
            .copied()
    }

    /// Records `moment` for `product` and `cve` when the file records none; whether it did (AWR-2, AWR-3).
    pub fn record(&mut self, product: Option<&str>, cve: &str, moment: Moment) -> bool {
        let key = (product.map(str::to_owned), cve.to_owned());
        if self.moments.contains_key(&key) {
            return false;
        }
        self.moments.insert(key, moment);
        true
    }

    /// Writes the file whole, its missing parents created, sorted by product then CVE (AWR-7, AWR-8, AWR-9).
    ///
    /// # Errors
    /// [`FileError`] naming the path that cannot be written (AWR-11).
    pub fn write(&self) -> Result<(), FileError> {
        let entries: Vec<Value> = self
            .moments
            .iter()
            .map(|((product, cve), moment)| {
                json!({"product": product, "cve": cve, "awareSince": moment.to_string()})
            })
            .collect();
        let text = format!("{:#}\n", json!({ "awareness": entries }));
        let failed = |error| FileError {
            path: self.path.clone(),
            cause: Cause::Io(error),
            write: true,
        };
        if let Some(parent) = self
            .path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent).map_err(failed)?;
        }
        replace(&self.path, &text, ".forewarn-awareness-").map_err(failed)
    }
}

/// The moments of a document, or why it is not as AWR-7 says (AWR-10).
fn parse(document: &Value) -> Result<BTreeMap<(Option<String>, String), Moment>, String> {
    let entries = document
        .get("awareness")
        .and_then(Value::as_array)
        .ok_or("no array `awareness`")?;
    let mut moments = BTreeMap::new();
    for (index, entry) in entries.iter().enumerate() {
        let at = |why: &str| format!("entry {index}: {why}");
        let entry: &Map<String, Value> = entry.as_object().ok_or_else(|| at("not an object"))?;
        let product = match entry.get("product") {
            Some(Value::Null) => None,
            Some(Value::String(product)) => Some(product.clone()),
            _ => return Err(at("`product` is neither a string nor null")),
        };
        let cve = entry
            .get("cve")
            .and_then(Value::as_str)
            .ok_or_else(|| at("no string `cve`"))?;
        let text = entry
            .get("awareSince")
            .and_then(Value::as_str)
            .ok_or_else(|| at("no string `awareSince`"))?;
        let moment = parse_moment(text)
            .map_err(|why| at(&format!("`awareSince` {text} is not {why}")))?
            .moment;
        reporting_deadlines(moment, None).map_err(|error| at(&error.to_string()))?;
        if moments.insert((product, cve.to_owned()), moment).is_some() {
            return Err(at(&format!("{cve} recorded twice for its product")));
        }
    }
    Ok(moments)
}
