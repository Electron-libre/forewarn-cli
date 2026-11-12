//! Fetching the OSV archive of each ecosystem, `<base>/<ecosystem>/all.zip`, into a cache directory, and reading the
//! snapshot it holds (`specs/osv-reading.md`, ADR 0004). A request names only the ecosystem, never a package.

use std::fmt;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::process;
use std::time::SystemTime;

use forewarn_domain::vulnerability::Vulnerability;
use serde::{Deserialize, Serialize};

use crate::{ReadError, read_directory};

/// Where OSV publishes the archive of each ecosystem.
pub const OSV_ARCHIVES: &str = "https://osv-vulnerabilities.storage.googleapis.com";

/// The file of a snapshot directory holding its freshness; its name does not end in `.json`, so reading the records
/// skips it.
const FRESHNESS_FILE: &str = "forewarn-freshness";

/// When to download the archive of an ecosystem again (OSR-13).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refresh {
    /// When the cache holds no snapshot of it.
    IfMissing,
    /// Always.
    Always,
}

/// The archives of OSV, kept in a cache directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Archives {
    /// The cache: one directory per ecosystem, created when missing.
    pub cache: PathBuf,
    /// The URL the archives are downloaded from, [`OSV_ARCHIVES`] by default.
    pub base_url: String,
    pub refresh: Refresh,
}

/// The records of one ecosystem and how fresh they are.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub ecosystem: String,
    pub freshness: Freshness,
    pub vulnerabilities: Vec<Vulnerability>,
}

/// When and where the archive of a snapshot was downloaded (OSR-11).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Freshness {
    /// The time of the download, as the caller's clock gave it.
    pub downloaded_at: SystemTime,
    /// The URL the archive was downloaded from.
    pub url: String,
    /// The `Last-Modified` header of the download, as the server sent it.
    pub last_modified: Option<String>,
}

/// An ecosystem whose records could not be fetched, and why (OSR-18).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchError {
    pub ecosystem: String,
    pub cause: FetchCause,
}

/// Why the records of an ecosystem could not be fetched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FetchCause {
    /// The ecosystem name is not one a cache directory can be named after (OSR-17).
    InvalidName,
    /// The server cannot be reached or does not answer 200.
    Download { url: String, reason: String },
    /// The download is not a zip archive; the reason of the reader.
    NotZip(String),
    /// An entry of the archive names a path outside its directory.
    UnsafeEntry(String),
    /// A record of the archive cannot be read; the error names the entry.
    Record(ReadError),
    /// The cache directory cannot be read or written; the system's reason.
    Cache(String),
}

impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: ", self.ecosystem)?;
        match &self.cause {
            FetchCause::InvalidName => write!(
                f,
                "invalid ecosystem name {:?}: only ASCII letters, digits, `.`, `-` and `_`, not first `.`",
                self.ecosystem
            ),
            FetchCause::Download { url, reason } => write!(f, "cannot download {url}: {reason}"),
            FetchCause::NotZip(reason) => write!(f, "not a zip archive: {reason}"),
            FetchCause::UnsafeEntry(name) => write!(f, "unsafe archive entry {name:?}"),
            FetchCause::Record(error) => write!(f, "{error}"),
            FetchCause::Cache(reason) => write!(f, "cannot use the cache: {reason}"),
        }
    }
}

impl std::error::Error for FetchError {}

impl Archives {
    /// The archives of OSV, cached in `cache`.
    #[must_use]
    pub fn new(cache: PathBuf, refresh: Refresh) -> Self {
        Self {
            cache,
            base_url: OSV_ARCHIVES.to_owned(),
            refresh,
        }
    }

    /// Returns the snapshot of each ecosystem, in the order given, downloading its archive when the refresh policy
    /// says so; `now` is the time recorded for a download.
    ///
    /// # Errors
    ///
    /// The [`FetchError`] of the first ecosystem that cannot be fetched; a failed download leaves the snapshot the
    /// cache held before unchanged.
    pub fn fetch(&self, ecosystems: &[&str], now: SystemTime) -> Result<Vec<Snapshot>, FetchError> {
        ecosystems
            .iter()
            .map(|ecosystem| {
                self.snapshot(ecosystem, now).map_err(|cause| FetchError {
                    ecosystem: (*ecosystem).to_owned(),
                    cause,
                })
            })
            .collect()
    }

    fn snapshot(&self, ecosystem: &str, now: SystemTime) -> Result<Snapshot, FetchCause> {
        if !is_valid_name(ecosystem) {
            return Err(FetchCause::InvalidName);
        }
        let directory = self.cache.join(ecosystem);
        let cached = read_freshness(&directory)?;
        let freshness = match (self.refresh, cached) {
            (Refresh::IfMissing, Some(freshness)) => freshness,
            _ => self.download(ecosystem, &directory, now)?,
        };
        Ok(Snapshot {
            ecosystem: ecosystem.to_owned(),
            vulnerabilities: read_records(&directory)?,
            freshness,
        })
    }

    /// Downloads the archive of an ecosystem into a staging directory, reads it, then puts it in place of the former
    /// snapshot.
    fn download(
        &self,
        ecosystem: &str,
        directory: &Path,
        now: SystemTime,
    ) -> Result<Freshness, FetchCause> {
        fs::create_dir_all(&self.cache).map_err(|e| cache_error(&e))?;
        // The names of ecosystems never start with `.`: these paths are no snapshot's.
        let id = process::id();
        let staging = Scratch(self.cache.join(format!(".staging-{ecosystem}-{id}")));
        let download = Scratch(self.cache.join(format!(".download-{ecosystem}-{id}.zip")));
        let former = Scratch(self.cache.join(format!(".former-{ecosystem}-{id}")));
        staging.clear()?;
        fs::create_dir(&staging.0).map_err(|e| cache_error(&e))?;

        let url = format!(
            "{}/{ecosystem}/all.zip",
            self.base_url.trim_end_matches('/')
        );
        let last_modified = get(&url, &download.0)?;
        extract(&download.0, &staging.0)?;
        read_records(&staging.0)?;
        let freshness = Freshness {
            downloaded_at: now,
            url,
            last_modified,
        };
        let json = serde_json::to_vec(&freshness).map_err(|e| FetchCause::Cache(e.to_string()))?;
        fs::write(staging.0.join(FRESHNESS_FILE), json).map_err(|e| cache_error(&e))?;

        former.clear()?;
        if directory.exists() {
            fs::rename(directory, &former.0).map_err(|e| cache_error(&e))?;
        }
        if let Err(error) = fs::rename(&staging.0, directory) {
            // Puts the former snapshot back rather than leave the ecosystem with none.
            let _ = fs::rename(&former.0, directory);
            return Err(cache_error(&error));
        }
        Ok(freshness)
    }
}

/// Whether a name is one OSR-17 accepts: it names a directory of the cache and a path of the URL as it is.
fn is_valid_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

/// The freshness of the snapshot of a directory; none when the directory holds no complete snapshot.
fn read_freshness(directory: &Path) -> Result<Option<Freshness>, FetchCause> {
    match fs::read(directory.join(FRESHNESS_FILE)) {
        Ok(json) => serde_json::from_slice(&json)
            .map(Some)
            .map_err(|e| FetchCause::Cache(format!("{}: {e}", directory.display()))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(cache_error(&e)),
    }
}

/// Reads the records of a snapshot directory, an error on a record naming its entry rather than the cache path.
fn read_records(directory: &Path) -> Result<Vec<Vulnerability>, FetchCause> {
    read_directory(directory).map_err(|error| match error.path.strip_prefix(directory) {
        Ok(entry) if !entry.as_os_str().is_empty() => FetchCause::Record(ReadError {
            path: entry.to_path_buf(),
            cause: error.cause,
        }),
        _ => FetchCause::Cache(error.to_string()),
    })
}

/// Downloads a URL into a file; returns the `Last-Modified` header the server sent.
fn get(url: &str, file: &Path) -> Result<Option<String>, FetchCause> {
    let failed = |reason: String| FetchCause::Download {
        url: url.to_owned(),
        reason,
    };
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into();
    let response = agent.get(url).call().map_err(|e| failed(e.to_string()))?;
    if response.status() != 200 {
        return Err(failed(format!("the server answered {}", response.status())));
    }
    let last_modified = response
        .headers()
        .get("last-modified")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let mut output = File::create(file).map_err(|e| cache_error(&e))?;
    io::copy(&mut response.into_body().into_reader(), &mut output)
        .map_err(|e| failed(e.to_string()))?;
    Ok(last_modified)
}

/// Extracts the `.json` files at the top of a zip archive into a directory, refusing an entry that escapes it and
/// skipping every other entry.
fn extract(archive: &Path, directory: &Path) -> Result<(), FetchCause> {
    let file = File::open(archive).map_err(|e| cache_error(&e))?;
    let mut zip = zip::ZipArchive::new(file).map_err(|e| FetchCause::NotZip(e.to_string()))?;
    for index in 0..zip.len() {
        let mut entry = zip
            .by_index(index)
            .map_err(|e| FetchCause::NotZip(e.to_string()))?;
        let name = entry.name().to_owned();
        if name.starts_with('/') || name.contains('\\') || name.split('/').any(|part| part == "..")
        {
            return Err(FetchCause::UnsafeEntry(name));
        }
        if entry.is_dir() || name.contains('/') || !name.as_bytes().ends_with(b".json") {
            continue;
        }
        let mut output = File::create(directory.join(&name)).map_err(|e| cache_error(&e))?;
        io::copy(&mut entry, &mut output)
            .map_err(|e| FetchCause::NotZip(format!("{name}: {e}")))?;
    }
    Ok(())
}

fn cache_error(error: &io::Error) -> FetchCause {
    FetchCause::Cache(error.to_string())
}

/// A file or a directory of the cache that exists only during a download, removed when dropped.
struct Scratch(PathBuf);

impl Scratch {
    /// Removes what a former run may have left there.
    fn clear(&self) -> Result<(), FetchCause> {
        let removed = if self.0.is_dir() {
            fs::remove_dir_all(&self.0)
        } else {
            fs::remove_file(&self.0)
        };
        match removed {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(cache_error(&e)),
            _ => Ok(()),
        }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = self.clear();
    }
}
