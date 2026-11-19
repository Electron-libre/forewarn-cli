//! Fetching the OSV archive of each ecosystem, `<base>/<ecosystem>/all.zip`, into a cache directory, and reading the
//! snapshot it holds (`specs/osv-fetching.md`, ADR 0004). A request names only the ecosystem, never a package. The
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
    /// default (OSF-19).
    pub lock_wait: Duration,
}

/// The records of one ecosystem and how fresh they are.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub ecosystem: String,
    pub freshness: Freshness,
    pub vulnerabilities: Vec<Vulnerability>,
}

/// An ecosystem whose records could not be fetched, and why (OSF-18).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchError {
    pub ecosystem: String,
    pub cause: FetchCause,
}

/// Why the records of an ecosystem could not be fetched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FetchCause {
    /// The ecosystem name is not one a cache directory can be named after (OSF-17).
    InvalidName,
    /// The policy is [`Refresh::Offline`] and the cache holds no snapshot of the ecosystem.
    NotCached,
    /// Another fetch still handles the ecosystem in this cache once the wait is over (OSF-19).
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
    /// The policy is [`Refresh::Offline`] and the files of the snapshot differ from those its download stored (OSF-11).
    Damaged(Damage),
}

impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\"{}\": ", self.ecosystem)?;
        match &self.cause {
            FetchCause::InvalidName => write!(
                f,
                "invalid ecosystem name \"{}\": only ASCII letters, digits, `.`, `-`, `_` and `:`, not first `.` or `:`",
                self.ecosystem
            ),
            FetchCause::NotCached => write!(f, "not cached, and the refresh policy is offline"),
            FetchCause::Locked { waited } => {
                write!(f, "cache locked by another run, waited {waited:?}")
            }
            FetchCause::Download { url, reason } => write!(f, "cannot download {url}: {reason}"),
            FetchCause::NotZip(reason) => write!(f, "not a zip archive: {reason}"),
            FetchCause::UnsafeEntry(name) => write!(f, "unsafe archive entry \"{name}\""),
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
            forewarn_cache::Error::Download { url, reason, .. } => Self::Download { url, reason },
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
    /// An ecosystem `<parent>:<release>` whose archive the server answers 404, or that the cache does not hold under
    /// [`Refresh::Offline`], is read from the snapshot of `<parent>`, whose archive holds the records of every release
    /// (OSF-22, OSF-23); each snapshot is returned once, at the place of the first ecosystem it stands for.
    ///
    /// # Errors
    ///
    /// The [`FetchError`] of the first ecosystem that cannot be fetched, naming the ecosystem asked for; a failed
    /// download leaves the snapshot the cache held before unchanged.
    pub fn fetch(
        &self,
        ecosystems: &[impl AsRef<str>],
        clock: impl Fn() -> SystemTime,
    ) -> Result<Vec<Snapshot>, FetchError> {
        // One agent for every download, so that they share its connections.
        let agent = forewarn_cache::agent();
        let mut snapshots: Vec<Snapshot> = Vec::new();
        for ecosystem in ecosystems.iter().map(AsRef::as_ref) {
            let fetched = |name: &str| snapshots.iter().any(|s| s.ecosystem == name);
            if fetched(ecosystem) {
                continue;
            }
            let error = |cause| FetchError {
                ecosystem: ecosystem.to_owned(),
                cause,
            };
            match self.snapshot(ecosystem, &agent, &clock) {
                Ok(snapshot) => snapshots.push(snapshot),
                Err(Missing::Release(parent)) => {
                    if !fetched(parent) {
                        let snapshot = self
                            .snapshot(parent, &agent, &clock)
                            .map_err(|missing| error(missing.into_cause()))?;
                        snapshots.push(snapshot);
                    }
                }
                Err(Missing::No(cause)) => return Err(error(cause)),
            }
        }
        Ok(snapshots)
    }

    fn snapshot<'a>(
        &self,
        ecosystem: &'a str,
        agent: &ureq::Agent,
        clock: &impl Fn() -> SystemTime,
    ) -> Result<Snapshot, Missing<'a>> {
        if ecosystem.starts_with(':') || !is_path_segment(ecosystem, b":") {
            return Err(Missing::No(FetchCause::InvalidName));
        }
        // `Debian:13`: a `:` is no file name on Windows, and opens a scheme in a relative URL (OSF-14, OSF-21).
        let entry = ecosystem.replace(':', "%3A");
        let cache = Cache {
            directory: self.cache.clone(),
            refresh: self.refresh,
            lock_wait: self.lock_wait,
        };
        let source = Source {
            url: format!("{}/{entry}/all.zip", self.base_url.trim_end_matches('/')),
            download: &forewarn_cache::get,
            unpack: &extract,
            read: &read_records,
        };
        match cache.fetch(agent, &entry, &source, clock) {
            Ok(Fetched { value, freshness }) => Ok(Snapshot {
                ecosystem: ecosystem.to_owned(),
                freshness,
                vulnerabilities: value,
            }),
            Err(error) => {
                let unpublished = matches!(
                    error,
                    forewarn_cache::Error::NotCached
                        | forewarn_cache::Error::Download {
                            status: Some(404),
                            ..
                        }
                );
                match ecosystem.split_once(':') {
                    Some((parent, _)) if unpublished => Err(Missing::Release(parent)),
                    _ => Err(Missing::No(error.into())),
                }
            }
        }
    }
}

/// Why the snapshot of an ecosystem was not returned.
enum Missing<'a> {
    /// The ecosystem is a release of this parent, whose archive the server does not publish (404), or which the cache
    /// does not hold under [`Refresh::Offline`] (OSF-22, OSF-23).
    Release(&'a str),
    /// The cause of the failure.
    No(FetchCause),
}

impl Missing<'_> {
    /// The cause of the failure; the parent of a release, missing itself, has none of its own.
    fn into_cause(self) -> FetchCause {
        match self {
            Self::Release(_) => FetchCause::NotCached,
            Self::No(cause) => cause,
        }
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
        let name = entry
            .name()
            .map_err(|e| FetchCause::NotZip(e.to_string()))?
            .into_owned();
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
