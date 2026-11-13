//! Fetching the OSV archive of each ecosystem, `<base>/<ecosystem>/all.zip`, into a cache directory, and reading the
//! snapshot it holds (`specs/osv-reading.md`, ADR 0004). A request names only the ecosystem, never a package. The
//! refresh policy, the freshness and the lock of each ecosystem are those of `forewarn-cache` (ADR 0008).

use std::fmt;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use forewarn_cache::{Cache, Fetched, Source};
pub use forewarn_cache::{Change, DEFAULT_LOCK_WAIT, Damage, Freshness, Refresh};
use forewarn_domain::vulnerability::Vulnerability;

use crate::{ReadError, is_path_segment, read_directory};

/// Where OSV publishes the archive of each ecosystem.
pub const OSV_ARCHIVES: &str = "https://osv-vulnerabilities.storage.googleapis.com";

/// The archives of OSV, kept in a cache directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Archives {
    /// The cache: one directory per ecosystem, created when missing.
    pub cache: PathBuf,
    /// The URL the archives are downloaded from, [`OSV_ARCHIVES`] by default.
    pub base_url: String,
    pub refresh: Refresh,
    /// How long a fetch waits for another fetch of the same ecosystem into this cache, [`DEFAULT_LOCK_WAIT`] by
    /// default (OSR-22).
    pub lock_wait: Duration,
}

/// The records of one ecosystem and how fresh they are.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub ecosystem: String,
    pub freshness: Freshness,
    pub vulnerabilities: Vec<Vulnerability>,
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
    /// The policy is [`Refresh::Offline`] and the cache holds no snapshot of the ecosystem.
    NotCached,
    /// Another fetch still handles the ecosystem in this cache once the wait is over (OSR-22).
    Locked { waited: Duration },
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
    /// The policy is [`Refresh::Offline`] and the files of the snapshot differ from those its download stored (OSR-39).
    Damaged(Damage),
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
            FetchCause::NotCached => write!(f, "not cached, and the refresh policy is offline"),
            FetchCause::Locked { waited } => {
                write!(f, "cache locked by another run, waited {waited:?}")
            }
            FetchCause::Download { url, reason } => write!(f, "cannot download {url}: {reason}"),
            FetchCause::NotZip(reason) => write!(f, "not a zip archive: {reason}"),
            FetchCause::UnsafeEntry(name) => write!(f, "unsafe archive entry {name:?}"),
            FetchCause::Record(error) => write!(f, "{error}"),
            FetchCause::Cache(reason) => write!(f, "cannot use the cache: {reason}"),
            FetchCause::Damaged(damage) => write!(f, "{damage}"),
        }
    }
}

impl std::error::Error for FetchError {}

impl From<forewarn_cache::Error<FetchCause>> for FetchCause {
    fn from(error: forewarn_cache::Error<FetchCause>) -> Self {
        match error {
            forewarn_cache::Error::NotCached => Self::NotCached,
            forewarn_cache::Error::Locked { waited } => Self::Locked { waited },
            forewarn_cache::Error::Download { url, reason } => Self::Download { url, reason },
            forewarn_cache::Error::Cache(reason) => Self::Cache(reason),
            forewarn_cache::Error::Damaged(damage) => Self::Damaged(damage),
            forewarn_cache::Error::Source(cause) => cause,
        }
    }
}

impl Archives {
    /// The archives of OSV, cached in `cache`.
    #[must_use]
    pub fn new(cache: PathBuf, refresh: Refresh) -> Self {
        Self {
            cache,
            base_url: OSV_ARCHIVES.to_owned(),
            refresh,
            lock_wait: DEFAULT_LOCK_WAIT,
        }
    }

    /// Returns the snapshot of each ecosystem, in the order given, downloading its archive when the refresh policy
    /// says so; `clock` gives the time the policy compares with and the time recorded for a download, read when the
    /// request of that download starts.
    ///
    /// # Errors
    ///
    /// The [`FetchError`] of the first ecosystem that cannot be fetched; a failed download leaves the snapshot the
    /// cache held before unchanged.
    pub fn fetch(
        &self,
        ecosystems: &[&str],
        clock: impl Fn() -> SystemTime,
    ) -> Result<Vec<Snapshot>, FetchError> {
        // One agent for every download, so that they share its connections.
        let agent = forewarn_cache::agent();
        ecosystems
            .iter()
            .map(|ecosystem| {
                self.snapshot(ecosystem, &agent, &clock)
                    .map_err(|cause| FetchError {
                        ecosystem: (*ecosystem).to_owned(),
                        cause,
                    })
            })
            .collect()
    }

    fn snapshot(
        &self,
        ecosystem: &str,
        agent: &ureq::Agent,
        clock: &impl Fn() -> SystemTime,
    ) -> Result<Snapshot, FetchCause> {
        if !is_path_segment(ecosystem, b"") {
            return Err(FetchCause::InvalidName);
        }
        let cache = Cache {
            directory: self.cache.clone(),
            refresh: self.refresh,
            lock_wait: self.lock_wait,
        };
        let source = Source {
            url: format!(
                "{}/{ecosystem}/all.zip",
                self.base_url.trim_end_matches('/')
            ),
            download: &forewarn_cache::get,
            unpack: &extract,
            read: &read_records,
        };
        let Fetched { value, freshness } = cache.fetch(agent, ecosystem, &source, clock)?;
        Ok(Snapshot {
            ecosystem: ecosystem.to_owned(),
            freshness,
            vulnerabilities: value,
        })
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
        if entry.enclosed_name().is_none()
            || name.starts_with('/')
            || name.contains('\\')
            || name.split('/').any(|part| part == "..")
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
