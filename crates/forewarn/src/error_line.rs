//! The line of standard error of an error that names a file: its path printed as `escape::escaped_path` does, the rest
//! escaped as any value (MCH-23, CHK-16, MCH-43).

use std::path::Path;

use forewarn_exploited::{euvd, kev};
use forewarn_osv::ReadError as OsvReadError;
use forewarn_osv::api::QueryError;
use forewarn_osv::fetch::{FetchCause, FetchError};

use crate::escape::{escaped, escaped_path};

/// An error printed on one line of standard error, after `error: `.
pub trait ErrorLine {
    /// The text of the line, escaped.
    fn line(&self) -> String;
}

/// `path`, then `: ` and `cause`, each escaped its own way: the line of an error the CLI words itself.
pub fn path_and_cause(path: &Path, cause: &impl ToString) -> String {
    format!("{}: {}", escaped_path(path), escaped(&cause.to_string()))
}

/// `whole`, the text of an error, its first `part` printed as `part_line` and the rest escaped, so that the wording
/// stays the adapter's.
fn around(whole: &str, part: &str, part_line: &str) -> String {
    match whole.split_once(part) {
        Some((before, after)) => escaped(before) + part_line + &escaped(after),
        None => escaped(whole),
    }
}

/// The line of an adapter's error that opens on the path of its file.
fn naming(error: &impl ToString, path: &Path) -> String {
    around(
        &error.to_string(),
        &path.display().to_string(),
        &escaped_path(path),
    )
}

/// The line of an error whose text holds the text of `inner`, printed as its own line.
fn holding(error: &impl ToString, inner: &(impl ToString + ErrorLine)) -> String {
    around(&error.to_string(), &inner.to_string(), &inner.line())
}

impl ErrorLine for OsvReadError {
    fn line(&self) -> String {
        naming(self, &self.path)
    }
}

impl ErrorLine for FetchError {
    fn line(&self) -> String {
        match &self.cause {
            FetchCause::Record(error) => holding(self, error),
            _ => escaped(&self.to_string()),
        }
    }
}

impl ErrorLine for QueryError {
    fn line(&self) -> String {
        // A record of the API is named by its id, never by a path.
        escaped(&self.to_string())
    }
}

impl ErrorLine for kev::ReadError {
    fn line(&self) -> String {
        naming(self, &self.path)
    }
}

impl ErrorLine for kev::FetchError {
    fn line(&self) -> String {
        match self {
            Self::Catalog(error) => holding(self, error),
            _ => escaped(&self.to_string()),
        }
    }
}

impl ErrorLine for euvd::ReadError {
    fn line(&self) -> String {
        naming(self, &self.path)
    }
}

impl ErrorLine for euvd::FetchError {
    fn line(&self) -> String {
        match self {
            Self::List(error) => holding(self, error),
            _ => escaped(&self.to_string()),
        }
    }
}
