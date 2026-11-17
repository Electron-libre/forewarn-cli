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

/// `path`, then `: ` and `cause`, each escaped its own way.
pub fn path_and_cause(path: &Path, cause: &impl ToString) -> String {
    format!("{}: {}", escaped_path(path), escaped(&cause.to_string()))
}

impl ErrorLine for OsvReadError {
    fn line(&self) -> String {
        path_and_cause(&self.path, &self.cause)
    }
}

impl ErrorLine for FetchError {
    fn line(&self) -> String {
        match &self.cause {
            // The prefix of `FetchError`'s `Display`, then the record's path its own way.
            FetchCause::Record(error) => {
                escaped(&format!("\"{}\": ", self.ecosystem)) + &error.line()
            }
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
        path_and_cause(&self.path, &self.cause)
    }
}

impl ErrorLine for kev::FetchError {
    fn line(&self) -> String {
        match self {
            Self::Catalog(error) => escaped(&format!("{}: ", kev::LIST_NAME)) + &error.line(),
            _ => escaped(&self.to_string()),
        }
    }
}

impl ErrorLine for euvd::ReadError {
    fn line(&self) -> String {
        path_and_cause(&self.path, &self.cause)
    }
}

impl ErrorLine for euvd::FetchError {
    fn line(&self) -> String {
        match self {
            Self::List(error) => escaped(&format!("{}: ", euvd::LIST_NAME)) + &error.line(),
            _ => escaped(&self.to_string()),
        }
    }
}
