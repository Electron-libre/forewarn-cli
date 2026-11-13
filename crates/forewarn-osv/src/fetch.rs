//! Fetching the OSV archive of each ecosystem, `<base>/<ecosystem>/all.zip`, into a cache directory, and reading the
//! snapshot it holds (`specs/osv-reading.md`, ADR 0004). A request names only the ecosystem, never a package.

use std::fmt;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use forewarn_domain::vulnerability::Vulnerability;
use serde::{Deserialize, Serialize};

use crate::{ReadError, is_path_segment, read_directory};

/// Where OSV publishes the archive of each ecosystem.
pub const OSV_ARCHIVES: &str = "https://osv-vulnerabilities.storage.googleapis.com";

/// How long a download waits to connect, for the response, and for the whole body.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(60);
const BODY_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// How long a fetch waits by default for another fetch of the same ecosystem: longer than the timeouts of a download
/// allow, so that it outlasts any live download (OSR-22, ADR 0005).
pub const DEFAULT_LOCK_WAIT: Duration = Duration::from_secs(40 * 60);

/// How often a waiting fetch tries the lock again.
const LOCK_POLL: Duration = Duration::from_millis(200);

/// The file of a snapshot directory holding its freshness; its name does not end in `.json`, so reading the records
/// skips it.
const FRESHNESS_FILE: &str = "forewarn-freshness";

/// When to download the archive of an ecosystem again (OSR-13).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refresh {
    /// Never: the cache only, and no request.
    Offline,
    /// When the cache holds no snapshot of it.
    IfMissing,
    /// When the cache holds no snapshot of it, or one downloaded more than this long before now.
    OlderThan(Duration),
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
        let agent = agent();
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
        // One bound for both locks of the fetch (OSR-22); a bound too large to add to now waits without one.
        let deadline = Instant::now().checked_add(self.lock_wait);
        let mut lock = self.lock_file(ecosystem)?;
        let directory = self.cache.join(ecosystem);
        let scratch = |kind: &str| self.cache.join(format!(".{kind}-{ecosystem}"));
        let former = scratch("former");
        // A run stopped between the two renames of a download left the snapshot there.
        let left_aside = || !directory.exists() && former.is_dir();

        // Under the shared lock, runs that read the snapshot read it together (OSR-32); `always` never reads it.
        let mut mode = if self.refresh == Refresh::Always {
            Mode::Exclusive
        } else {
            Mode::Shared
        };
        loop {
            self.wait_for(&mut lock, mode, deadline)?;
            if mode == Mode::Exclusive && left_aside() {
                fs::rename(&former, &directory).map_err(|e| cache_error(&e))?;
            }
            let freshness = if left_aside() {
                None
            } else {
                self.cached(&directory, clock)?
            };
            match (freshness, mode) {
                (Some(freshness), Mode::Shared) => {
                    return Ok(Snapshot {
                        ecosystem: ecosystem.to_owned(),
                        vulnerabilities: read_records(&directory)?,
                        freshness,
                    });
                }
                (None, Mode::Exclusive) => break,
                // A download, or putting the snapshot back, waits for every other run (OSR-19, OSR-33). Another run
                // may have downloaded while this one waited for the exclusive lock: it then reads the snapshot under
                // the shared lock, beside the other readers.
                (None, Mode::Shared) | (Some(_), Mode::Exclusive) => {
                    if let Some(file) = &lock {
                        file.unlock().map_err(|e| cache_error(&e))?;
                    }
                    mode = match mode {
                        Mode::Shared => Mode::Exclusive,
                        Mode::Exclusive => Mode::Shared,
                    };
                }
            }
        }
        let download = Download {
            agent,
            url: format!(
                "{}/{ecosystem}/all.zip",
                self.base_url.trim_end_matches('/')
            ),
            archive: Scratch(scratch("download")),
            staging: Scratch(scratch("staging")),
            former: Scratch(former),
        };
        let (freshness, vulnerabilities) = download.run(&directory, clock())?;
        Ok(Snapshot {
            ecosystem: ecosystem.to_owned(),
            freshness,
            vulnerabilities,
        })
    }

    /// The freshness of the snapshot of a directory when the refresh policy reads it rather than downloading the
    /// archive again (OSR-13); `clock` is read only by a policy that compares with the time.
    fn cached(
        &self,
        directory: &Path,
        clock: &impl Fn() -> SystemTime,
    ) -> Result<Option<Freshness>, FetchCause> {
        Ok(match (self.refresh, read_freshness(directory)?) {
            (Refresh::Offline, None) => return Err(FetchCause::NotCached),
            (Refresh::Offline | Refresh::IfMissing, Some(freshness)) => Some(freshness),
            // A snapshot dated after now (a clock set back) is not older than any age.
            (Refresh::OlderThan(age), Some(freshness))
                if clock()
                    .duration_since(freshness.downloaded_at)
                    .map_or(true, |elapsed| elapsed <= age) =>
            {
                Some(freshness)
            }
            _ => None,
        })
    }

    /// Opens the lock file of an ecosystem, `.lock-<ecosystem>` in the cache (ADR 0005, ADR 0007); the system releases
    /// its lock when the returned file is closed or the process ends. A lock file another user created is opened
    /// read-only, which locks it as well. Under `offline`, a cache the lock file cannot be opened in is read without it
    /// (OSR-23).
    fn lock_file(&self, ecosystem: &str) -> Result<Option<File>, FetchCause> {
        let path = self.cache.join(format!(".lock-{ecosystem}"));
        let offline = self.refresh == Refresh::Offline;
        if !offline {
            fs::create_dir_all(&self.cache).map_err(|e| cache_error(&e))?;
        }
        let opened = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            // Keeps the reason of the write when the lock file cannot be read either (a cache it cannot write in).
            .or_else(|error| File::open(&path).map_err(|_| error));
        match opened {
            Ok(file) => Ok(Some(file)),
            Err(_) if offline => Ok(None),
            Err(e) => Err(cache_error(&e)),
        }
    }

    /// Takes the lock of a lock file in a mode, polling until the deadline (none: without bound). On a platform
    /// without file locks, drops the file and goes on without a lock (ADR 0005).
    fn wait_for(
        &self,
        lock: &mut Option<File>,
        mode: Mode,
        deadline: Option<Instant>,
    ) -> Result<(), FetchCause> {
        let Some(file) = lock else {
            return Ok(());
        };
        loop {
            let tried = match mode {
                Mode::Shared => file.try_lock_shared(),
                Mode::Exclusive => file.try_lock(),
            };
            match tried {
                Ok(()) => return Ok(()),
                Err(TryLockError::WouldBlock) => {
                    let left = deadline.map_or(LOCK_POLL, |deadline| {
                        deadline.saturating_duration_since(Instant::now())
                    });
                    if left.is_zero() {
                        return Err(FetchCause::Locked {
                            waited: self.lock_wait,
                        });
                    }
                    thread::sleep(left.min(LOCK_POLL));
                }
                Err(TryLockError::Error(e)) if e.kind() == io::ErrorKind::Unsupported => {
                    *lock = None;
                    return Ok(());
                }
                Err(TryLockError::Error(e)) => return Err(cache_error(&e)),
            }
        }
    }
}

/// How a fetch holds the lock of an ecosystem: shared to read its snapshot, exclusive to replace it (ADR 0007).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Shared,
    Exclusive,
}

/// The download of the archive of an ecosystem, and the paths of the cache it goes through. Their names start with
/// `.`, which no ecosystem name does; the lock of the ecosystem keeps them to one run at a time (ADR 0005), so that a
/// run clears what a stopped one left.
struct Download<'a> {
    agent: &'a ureq::Agent,
    url: String,
    archive: Scratch,
    staging: Scratch,
    former: Scratch,
}

impl Download<'_> {
    /// Downloads the archive into the staging directory, reads it, then puts it in place of the former snapshot;
    /// `now` is the time recorded for the download.
    fn run(
        self,
        directory: &Path,
        now: SystemTime,
    ) -> Result<(Freshness, Vec<Vulnerability>), FetchCause> {
        self.staging.clear()?;
        fs::create_dir(&self.staging.0).map_err(|e| cache_error(&e))?;
        let last_modified = get(self.agent, &self.url, &self.archive.0)?;
        extract(&self.archive.0, &self.staging.0)?;
        let vulnerabilities = read_records(&self.staging.0)?;
        let freshness = Freshness {
            downloaded_at: now,
            url: self.url,
            last_modified,
        };
        let json = serde_json::to_vec(&freshness).map_err(|e| FetchCause::Cache(e.to_string()))?;
        fs::write(self.staging.0.join(FRESHNESS_FILE), json).map_err(|e| cache_error(&e))?;

        self.former.clear()?;
        if directory.exists() {
            fs::rename(directory, &self.former.0).map_err(|e| cache_error(&e))?;
        }
        if let Err(error) = fs::rename(&self.staging.0, directory) {
            // Puts the former snapshot back; when that fails too, keeps it where it is for the next run.
            if fs::rename(&self.former.0, directory).is_err() {
                std::mem::forget(self.former);
            }
            return Err(cache_error(&error));
        }
        Ok((freshness, vulnerabilities))
    }
}

/// An HTTP agent with the timeouts of a download, that leaves the status of a response to the caller.
pub(crate) fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_connect(Some(CONNECT_TIMEOUT))
        .timeout_recv_response(Some(RESPONSE_TIMEOUT))
        .timeout_recv_body(Some(BODY_TIMEOUT))
        .build()
        .into()
}

/// The freshness of the snapshot of a directory; none when the directory holds no snapshot, or one whose freshness
/// cannot be read (a later download replaces it).
fn read_freshness(directory: &Path) -> Result<Option<Freshness>, FetchCause> {
    match fs::read(directory.join(FRESHNESS_FILE)) {
        Ok(json) => Ok(serde_json::from_slice(&json).ok()),
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
fn get(agent: &ureq::Agent, url: &str, file: &Path) -> Result<Option<String>, FetchCause> {
    let failed = |reason: String| FetchCause::Download {
        url: url.to_owned(),
        reason,
    };
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
