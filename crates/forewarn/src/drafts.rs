//! The files of the draft early warnings of `forewarn match --drafts <dir>`: one per CVE, named after the product and
//! the CVE, written whole or not at all (`specs/cli-match-exploited.md`, MXL-27 to MXL-34).

use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use forewarn_domain::early_warning::EarlyWarning;

use crate::early_warning;

/// The characters of the product name kept in a file name (MXL-31).
const PRODUCT_NAME_LENGTH: usize = 100;

/// A draft written to its file, which the report names (MXL-28).
pub struct Written {
    pub cve: String,
    pub path: PathBuf,
}

/// A draft, or the directory of the drafts, that could not be written (MXL-33).
pub struct WriteError {
    path: PathBuf,
    error: io::Error,
}

impl fmt::Display for WriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "cannot write the draft early warning {}: {}",
            self.path.display(),
            self.error
        )
    }
}

/// Writes each draft in Markdown into `directory`, created with its parents when there is a draft (MXL-30, MXL-32).
///
/// # Errors
/// [`WriteError`] naming the directory or the file that could not be written, at the first one.
pub fn write(directory: &Path, drafts: &[EarlyWarning]) -> Result<Vec<Written>, WriteError> {
    if drafts.is_empty() {
        return Ok(Vec::new());
    }
    fs::create_dir_all(directory).map_err(|error| WriteError {
        path: directory.to_owned(),
        error,
    })?;
    drafts
        .iter()
        .map(|draft| {
            let path = directory.join(file_name(draft));
            replace(&path, &early_warning::markdown(draft))
                .map_err(|error| WriteError {
                    path: path.clone(),
                    error,
                })
                .map(|()| Written {
                    cve: draft.cve.clone(),
                    path,
                })
        })
        .collect()
}

/// `<product>-<CVE id>.md`, or `<CVE id>.md` with no product name (MXL-31). The CVE id, read as `CVE-<year>-<digits>`
/// (EXF-7), is kept to the same characters as the product name, so that no id names a path out of the directory.
fn file_name(draft: &EarlyWarning) -> String {
    let cve = safe(draft.cve.chars());
    match &draft.product_name {
        Some(product) => {
            let product = safe(product.trim().chars().take(PRODUCT_NAME_LENGTH));
            format!("{product}-{cve}.md")
        }
        None => format!("{cve}.md"),
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

/// Writes `text` to a new temporary file of a random name beside `path`, flushed to the disk, then renames it over
/// `path`, so that `path` holds either its former content or the whole text (MXL-34); the temporary file is removed
/// when a step fails.
fn replace(path: &Path, text: &str) -> io::Result<()> {
    let directory = path.parent().unwrap_or(Path::new("."));
    let mut temporary = tempfile::Builder::new()
        .prefix(".forewarn-draft-")
        .suffix(".tmp")
        .tempfile_in(directory)?;
    temporary.write_all(text.as_bytes())?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    Ok(())
}
