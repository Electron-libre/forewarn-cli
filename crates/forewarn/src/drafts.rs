//! The files of the draft early warnings of `forewarn match --drafts <dir>`: one per CVE, named after the product and
//! the CVE, written whole or not at all, and the stale drafts of the product the run no longer writes, left in place
//! (`specs/cli-match-exploited.md`, MXL-27 to MXL-34, MXL-36 to MXL-40).

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use forewarn_domain::early_warning::EarlyWarning;
use forewarn_domain::is_cve;

use crate::early_warning;
use crate::error_line::ErrorLine;
use crate::escape::{escaped, escaped_path};

/// The characters of the product name kept in a file name (MXL-31).
const PRODUCT_NAME_LENGTH: usize = 100;

/// The draft files of a run: those it wrote (MXL-28) and the stale ones (MXL-36).
pub struct Drafts {
    pub written: Vec<DraftFile>,
    /// Sorted by file name (MXL-39).
    pub stale: Vec<DraftFile>,
}

/// A draft file and its CVE, which the report names.
pub struct DraftFile {
    pub cve: String,
    pub path: PathBuf,
}

/// A draft, or the directory of the drafts, that could not be written (MXL-33) or listed (MXL-40).
pub struct WriteError {
    kind: Failure,
    path: PathBuf,
    error: io::Error,
}

enum Failure {
    Write,
    List,
}

impl ErrorLine for WriteError {
    fn line(&self) -> String {
        let what = match self.kind {
            Failure::Write => "cannot write the draft early warning ",
            Failure::List => "cannot list the draft early warnings of ",
        };
        format!(
            "{what}{}: {}",
            escaped_path(&self.path),
            escaped(&self.error.to_string())
        )
    }
}

/// Lists the stale drafts of `product` that `directory` holds, a path naming no directory holding none (MXL-36,
/// MXL-40), then writes each draft in Markdown into `directory`, created with its parents when there is a draft (MXL-30,
/// MXL-32): a directory that cannot be listed leaves no draft written.
///
/// # Errors
/// [`WriteError`] naming the directory that could not be listed, or the directory or the file that could not be
/// written, at the first one.
pub fn write(
    directory: &Path,
    product: Option<&str>,
    drafts: &[EarlyWarning],
) -> Result<Drafts, WriteError> {
    let prefix = product_prefix(product);
    let names: Vec<String> = drafts
        .iter()
        .map(|draft| format!("{prefix}{}.md", safe(draft.cve.chars())))
        .collect();
    let stale = stale(directory, &prefix, &names).map_err(|error| WriteError {
        kind: Failure::List,
        path: directory.to_owned(),
        error,
    })?;
    if !drafts.is_empty() {
        fs::create_dir_all(directory).map_err(|error| WriteError {
            kind: Failure::Write,
            path: directory.to_owned(),
            error,
        })?;
    }
    let written = drafts
        .iter()
        .zip(names)
        .map(|(draft, name)| {
            let path = directory.join(name);
            replace(&path, &early_warning::markdown(draft), ".forewarn-draft-")
                .map_err(|error| WriteError {
                    kind: Failure::Write,
                    path: path.clone(),
                    error,
                })
                .map(|()| DraftFile {
                    cve: draft.cve.clone(),
                    path,
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Drafts { written, stale })
}

/// The files of `directory` named `<prefix><CVE id>.md` (MXL-38) other than the `names` the run writes, sorted by file
/// name (MXL-39); none when `directory` names no directory, and no file removed while it is listed.
fn stale(directory: &Path, prefix: &str, names: &[String]) -> io::Result<Vec<DraftFile>> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if absent(&error) => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let mut stale = Vec::new();
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let Some(cve) = name
            .to_str()
            .filter(|name| !names.iter().any(|written| written == name))
            .and_then(|name| name.strip_prefix(prefix))
            .and_then(|rest| rest.strip_suffix(".md"))
            .filter(|cve| cve.starts_with("CVE-") && is_cve(cve))
        else {
            continue;
        };
        match entry.file_type() {
            Ok(kind) if kind.is_file() => stale.push(DraftFile {
                cve: cve.to_owned(),
                path: directory.join(&name),
            }),
            Ok(_) => {}
            Err(error) if absent(&error) => {}
            Err(error) => return Err(error),
        }
    }
    stale.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(stale)
}

/// Whether `error` says the path names nothing, or lies under a file (MXL-40).
fn absent(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
    )
}

/// What the file name of a draft of `product` holds before its CVE id: `<product>-`, or nothing with no product name
/// or one made only of white space (MXL-31). The CVE id that follows, read as `CVE-<year>-<digits>` (EXF-7), is kept
/// to the same characters as the product name, so that no id names a path out of the directory.
fn product_prefix(product: Option<&str>) -> String {
    match product.map(str::trim).filter(|product| !product.is_empty()) {
        Some(product) => format!("{}-", safe(product.chars().take(PRODUCT_NAME_LENGTH))),
        None => String::new(),
    }
}

/// The characters, each other than an ASCII letter or digit, `.`, `_` or `-` replaced by `_` (MXL-31).
fn safe(characters: impl Iterator<Item = char>) -> String {
    characters
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Writes `text` to a new temporary file of a random name opening on `prefix` beside `path`, flushed to the disk, then
/// renames it over `path`, so that `path` holds either its former content or the whole text (MXL-34, AWR-9); the
/// temporary file is removed when a step fails.
pub(crate) fn replace(path: &Path, text: &str, prefix: &str) -> io::Result<()> {
    let directory = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut temporary = tempfile::Builder::new()
        .prefix(prefix)
        .suffix(".tmp")
        .tempfile_in(directory)?;
    temporary.write_all(text.as_bytes())?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    Ok(())
}
