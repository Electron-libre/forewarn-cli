//! The files of the draft early warnings of `forewarn match --drafts <dir>`: one per CVE, named after the product and
//! the CVE, written whole or not at all, and the stale drafts of the product the run no longer writes, left in place
//! (`specs/cli-match-exploited.md`, MXL-27 to MXL-34, MXL-36 to MXL-40).

use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use forewarn_domain::early_warning::EarlyWarning;

use crate::early_warning;

/// The characters of the product name kept in a file name (MXL-31).
const PRODUCT_NAME_LENGTH: usize = 100;

/// The drafts of a run: those written (MXL-28) and the stale ones (MXL-36).
pub struct Drafts {
    pub written: Vec<Written>,
    /// Sorted by file name (MXL-39).
    pub stale: Vec<Written>,
}

/// A draft file and its CVE: written by the run (MXL-28), or stale (MXL-36).
pub struct Written {
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

impl fmt::Display for WriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            Failure::Write => write!(
                f,
                "cannot write the draft early warning {}",
                self.path.display()
            )?,
            Failure::List => write!(
                f,
                "cannot list the draft early warnings of {}",
                self.path.display()
            )?,
        }
        write!(f, ": {}", self.error)
    }
}

/// Writes each draft in Markdown into `directory`, created with its parents when there is a draft (MXL-30, MXL-32),
/// then lists the stale drafts of `product` it holds, a directory that does not exist holding none (MXL-36, MXL-40).
///
/// # Errors
/// [`WriteError`] naming the directory or the file that could not be written, at the first one, or the directory that
/// could not be listed.
pub fn write(
    directory: &Path,
    product: Option<&str>,
    drafts: &[EarlyWarning],
) -> Result<Drafts, WriteError> {
    if !drafts.is_empty() {
        fs::create_dir_all(directory).map_err(|error| WriteError {
            kind: Failure::Write,
            path: directory.to_owned(),
            error,
        })?;
    }
    let written = drafts
        .iter()
        .map(|draft| {
            let path = directory.join(file_name(draft.product_name.as_deref(), &draft.cve));
            replace(&path, &early_warning::markdown(draft))
                .map_err(|error| WriteError {
                    kind: Failure::Write,
                    path: path.clone(),
                    error,
                })
                .map(|()| Written {
                    cve: draft.cve.clone(),
                    path,
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let stale = stale(directory, product, &written).map_err(|error| WriteError {
        kind: Failure::List,
        path: directory.to_owned(),
        error,
    })?;
    Ok(Drafts { written, stale })
}

/// The files of `directory` named as a draft of `product` that the run did not write, sorted by file name (MXL-38,
/// MXL-39); none when the directory does not exist.
fn stale(directory: &Path, product: Option<&str>, written: &[Written]) -> io::Result<Vec<Written>> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let prefix = product_prefix(product);
    let mut stale = Vec::new();
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name();
        let Some(cve) = name
            .to_str()
            .and_then(|name| name.strip_prefix(&prefix))
            .and_then(|rest| rest.strip_suffix(".md"))
            .filter(|cve| is_cve_id(cve))
        else {
            continue;
        };
        if written.iter().all(|draft| draft.cve != cve) {
            stale.push(Written {
                cve: cve.to_owned(),
                path: directory.join(&name),
            });
        }
    }
    stale.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(stale)
}

/// `CVE-`, four digits, `-`, four digits or more, in capitals (MXL-38).
fn is_cve_id(text: &str) -> bool {
    let all_digits = |part: &str| part.bytes().all(|byte| byte.is_ascii_digit());
    text.strip_prefix("CVE-")
        .and_then(|rest| rest.split_once('-'))
        .is_some_and(|(year, number)| {
            year.len() == 4 && all_digits(year) && number.len() >= 4 && all_digits(number)
        })
}

/// `<product>-<CVE id>.md`, or `<CVE id>.md` with no product name (MXL-31). The CVE id, read as `CVE-<year>-<digits>`
/// (EXF-7), is kept to the same characters as the product name, so that no id names a path out of the directory.
fn file_name(product: Option<&str>, cve: &str) -> String {
    format!("{}{}.md", product_prefix(product), safe(cve.chars()))
}

/// What the file name of a draft of `product` holds before its CVE id: `<product>-`, or nothing with no product name
/// or one made only of white space (MXL-31).
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
