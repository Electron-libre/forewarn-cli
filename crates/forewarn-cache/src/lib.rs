//! The cache of the downloads of `forewarn` (ADR 0008): one directory per entry (an OSV ecosystem, the KEV catalog),
//! downloaded again as a refresh policy says (ADR 0004), beside the freshness of its download, and a file lock per
//! entry, shared by the runs that read it and exclusive for the run that replaces it (ADRs 0005, 0007). What a
//! download holds and how it is read is the source's: it hands [`Cache::fetch`] two functions.

use std::fmt;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};

/// How long a download waits to connect, for the response, and for the whole body.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(60);
const BODY_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// How long a fetch waits by default for another fetch of the same entry: longer than the timeouts of a download
/// allow, so that it outlasts any live download (ADR 0005).
pub const DEFAULT_LOCK_WAIT: Duration = Duration::from_secs(40 * 60);

/// How often a waiting fetch tries the lock again.
const LOCK_POLL: Duration = Duration::from_millis(200);

/// The file of an entry directory holding its freshness; its name does not end in `.json`, so reading the entry can
/// skip it.
pub const FRESHNESS_FILE: &str = "forewarn-freshness";

/// When to download an entry again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refresh {
    /// Never: the cache only, and no request.
    Offline,
    /// When the cache holds no copy of it.
    IfMissing,
    /// When the cache holds no copy of it, or one downloaded more than this long before now.
    OlderThan(Duration),
    /// Always.
    Always,
}

/// When and where the copy of an entry was downloaded.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Freshness {
    /// The time of the download, as the caller's clock gave it.
    pub downloaded_at: SystemTime,
    /// The URL it was downloaded from.
    pub url: String,
    /// The `Last-Modified` header of the download, as the server sent it.
    pub last_modified: Option<String>,
}

/// What a fetch read from an entry, and how fresh it is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fetched<T> {
    pub value: T,
    pub freshness: Freshness,
}

/// Why an entry could not be fetched; `E` is the error of the source's own functions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error<E> {
    /// The policy is [`Refresh::Offline`] and the cache holds no copy of the entry.
    NotCached,
    /// Another fetch still handles the entry in this cache once the wait is over.
    Locked { waited: Duration },
    /// The server cannot be reached or does not answer 200.
    Download { url: String, reason: String },
    /// The cache directory cannot be read or written; the system's reason.
    Cache(String),
    /// The source could not unpack or read the download, or read the entry.
    Source(E),
}

impl<E: fmt::Display> fmt::Display for Error<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotCached => write!(f, "not cached, and the refresh policy is offline"),
            Self::Locked { waited } => write!(f, "cache locked by another run, waited {waited:?}"),
            Self::Download { url, reason } => write!(f, "cannot download {url}: {reason}"),
            Self::Cache(reason) => write!(f, "cannot use the cache: {reason}"),
            Self::Source(error) => write!(f, "{error}"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for Error<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Source(error) => Some(error),
            _ => None,
        }
    }
}

/// A cache directory: one directory per entry, created when missing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cache {
    pub directory: PathBuf,
    pub refresh: Refresh,
    /// How long a fetch waits for another fetch of the same entry into this cache, [`DEFAULT_LOCK_WAIT`] by default.
    pub lock_wait: Duration,
}

/// How a source downloads a URL into a file, returning the `Last-Modified` header it records.
pub type DownloadFn<'a, E> =
    dyn Fn(&ureq::Agent, &str, &Path) -> Result<Option<String>, Error<E>> + 'a;

/// What a fetch does with a download, and how it reads an entry.
pub struct Source<'a, T, E> {
    /// The URL of the download, recorded in its freshness.
    pub url: String,
    /// Downloads the URL (second argument) into a file (third argument) and returns the `Last-Modified` header it
    /// records: [`get`], one `GET`, for a single file; a paginated source pages there (ADR 0009).
    pub download: &'a DownloadFn<'a, E>,
    /// Turns the downloaded file (first argument) into the files of an entry directory (second argument).
    pub unpack: &'a dyn Fn(&Path, &Path) -> Result<(), E>,
    /// Reads an entry directory.
    pub read: &'a dyn Fn(&Path) -> Result<T, E>,
}

impl Cache {
    /// A cache in `directory`, waiting [`DEFAULT_LOCK_WAIT`] for another fetch.
    #[must_use]
    pub fn new(directory: PathBuf, refresh: Refresh) -> Self {
        Self {
            directory,
            refresh,
            lock_wait: DEFAULT_LOCK_WAIT,
        }
    }

    /// Returns what the source reads from the entry `name`, downloading it again when the refresh policy says so;
    /// `clock` gives the time the policy compares with and the time recorded for a download, read when its request
    /// starts.
    ///
    /// # Errors
    ///
    /// The [`Error`] that stops the fetch; a failed download leaves the copy the cache held before unchanged. A `name`
    /// that is empty, starts with `.` (the scratch paths of the cache do), or holds a character other than an ASCII
    /// letter, a digit, `.`, `-` and `_` fails with [`Error::Cache`] before the cache is touched.
    pub fn fetch<T, E>(
        &self,
        agent: &ureq::Agent,
        name: &str,
        source: &Source<'_, T, E>,
        clock: &impl Fn() -> SystemTime,
    ) -> Result<Fetched<T>, Error<E>> {
        if !is_entry_name(name) {
            return Err(Error::Cache(format!("invalid entry name {name:?}")));
        }
        // One bound for both locks of the fetch; a bound too large to add to now waits without one.
        let deadline = Instant::now().checked_add(self.lock_wait);
        let mut lock = self.lock_file(name)?;
        let directory = self.directory.join(name);
        let scratch = |kind: &str| self.directory.join(format!(".{kind}-{name}"));
        let former = scratch("former");
        // A run stopped between the two renames of a download left the copy there.
        let left_aside = || !directory.exists() && former.is_dir();

        // Under the shared lock, runs that read the copy read it together (ADR 0007); `always` never reads it.
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
                    return Ok(Fetched {
                        value: (source.read)(&directory).map_err(Error::Source)?,
                        freshness,
                    });
                }
                (None, Mode::Exclusive) => break,
                // A download, or putting the copy back, waits for every other run. Another run may have downloaded
                // while this one waited for the exclusive lock: it then reads the copy under the shared lock, beside
                // the other readers.
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
            file: Scratch(scratch("download")),
            staging: Scratch(scratch("staging")),
            former: Scratch(former),
        };
        download.run(source, &directory, clock())
    }

    /// The freshness of the copy of a directory when the refresh policy reads it rather than downloading it again;
    /// `clock` is read only by a policy that compares with the time.
    fn cached<E>(
        &self,
        directory: &Path,
        clock: &impl Fn() -> SystemTime,
    ) -> Result<Option<Freshness>, Error<E>> {
        Ok(match (self.refresh, read_freshness(directory)?) {
            (Refresh::Offline, None) => return Err(Error::NotCached),
            (Refresh::Offline | Refresh::IfMissing, Some(freshness)) => Some(freshness),
            // A copy dated after now (a clock set back) is not older than any age.
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

    /// Opens the lock file of an entry, `.lock-<name>` in the cache (ADR 0005, ADR 0007); the system releases its lock
    /// when the returned file is closed or the process ends. A lock file another user created is opened read-only,
    /// which locks it as well. Under `offline`, a cache the lock file cannot be opened in is read without it.
    fn lock_file<E>(&self, name: &str) -> Result<Option<File>, Error<E>> {
        let path = self.directory.join(format!(".lock-{name}"));
        let offline = self.refresh == Refresh::Offline;
        if !offline {
            fs::create_dir_all(&self.directory).map_err(|e| cache_error(&e))?;
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
    fn wait_for<E>(
        &self,
        lock: &mut Option<File>,
        mode: Mode,
        deadline: Option<Instant>,
    ) -> Result<(), Error<E>> {
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
                        return Err(Error::Locked {
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

/// Whether a name can name an entry directory and its lock file as it is, and none of the scratch paths of the cache.
fn is_entry_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

/// How a fetch holds the lock of an entry: shared to read its copy, exclusive to replace it (ADR 0007).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Shared,
    Exclusive,
}

/// The download of an entry, and the paths of the cache it goes through. Their names start with `.`, which no entry
/// name does; the lock of the entry keeps them to one run at a time (ADR 0005), so that a run clears what a stopped
/// one left.
struct Download<'a> {
    agent: &'a ureq::Agent,
    file: Scratch,
    staging: Scratch,
    former: Scratch,
}

impl Download<'_> {
    /// Downloads into the staging directory, reads it, then puts it in place of the former copy; `now` is the time
    /// recorded for the download.
    fn run<T, E>(
        self,
        source: &Source<'_, T, E>,
        directory: &Path,
        now: SystemTime,
    ) -> Result<Fetched<T>, Error<E>> {
        self.staging.clear()?;
        fs::create_dir(&self.staging.0).map_err(|e| cache_error(&e))?;
        let last_modified = (source.download)(self.agent, &source.url, &self.file.0)?;
        (source.unpack)(&self.file.0, &self.staging.0).map_err(Error::Source)?;
        let value = (source.read)(&self.staging.0).map_err(Error::Source)?;
        let freshness = Freshness {
            downloaded_at: now,
            url: source.url.clone(),
            last_modified,
        };
        let json = serde_json::to_vec(&freshness).map_err(|e| Error::Cache(e.to_string()))?;
        fs::write(self.staging.0.join(FRESHNESS_FILE), json).map_err(|e| cache_error(&e))?;

        self.former.clear()?;
        if directory.exists() {
            fs::rename(directory, &self.former.0).map_err(|e| cache_error(&e))?;
        }
        if let Err(error) = fs::rename(&self.staging.0, directory) {
            // Puts the former copy back; when that fails too, keeps it where it is for the next run.
            if fs::rename(&self.former.0, directory).is_err() {
                std::mem::forget(self.former);
            }
            return Err(cache_error(&error));
        }
        Ok(Fetched { value, freshness })
    }
}

/// An HTTP agent with the timeouts of a download, that leaves the status of a response to the caller.
#[must_use]
pub fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_connect(Some(CONNECT_TIMEOUT))
        .timeout_recv_response(Some(RESPONSE_TIMEOUT))
        .timeout_recv_body(Some(BODY_TIMEOUT))
        .build()
        .into()
}

/// The freshness of the copy of a directory; none when the directory holds no copy, or one whose freshness cannot be
/// read (a later download replaces it).
fn read_freshness<E>(directory: &Path) -> Result<Option<Freshness>, Error<E>> {
    match fs::read(directory.join(FRESHNESS_FILE)) {
        Ok(json) => Ok(serde_json::from_slice(&json).ok()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(cache_error(&e)),
    }
}

/// Downloads a URL into a file with one `GET`; returns the `Last-Modified` header the server sent.
///
/// # Errors
///
/// [`Error::Download`] when the server cannot be reached or does not answer 200, [`Error::Cache`] when the file
/// cannot be written.
pub fn get<E>(agent: &ureq::Agent, url: &str, file: &Path) -> Result<Option<String>, Error<E>> {
    let (response, last_modified) = call(agent, url, None)?;
    let mut output = File::create(file).map_err(|e| cache_error(&e))?;
    io::copy(&mut response.into_body().into_reader(), &mut output)
        .map_err(|e| download_error(url, &e))?;
    Ok(last_modified)
}

/// Downloads a URL into memory with one `GET`, its body at most `limit` bytes and the whole request at most `timeout`
/// when one is given; returns the body and the `Last-Modified` header the server sent.
///
/// # Errors
///
/// [`Error::Download`] when the server cannot be reached, does not answer 200, sends a larger body or takes longer.
pub fn get_body<E>(
    agent: &ureq::Agent,
    url: &str,
    limit: u64,
    timeout: Option<Duration>,
) -> Result<(Vec<u8>, Option<String>), Error<E>> {
    let (response, last_modified) = call(agent, url, timeout)?;
    let body = response
        .into_body()
        .with_config()
        .limit(limit)
        .read_to_vec()
        .map_err(|e| download_error(url, &e))?;
    Ok((body, last_modified))
}

/// Sends a `GET` and checks that the server answers 200; returns the response and its `Last-Modified` header.
fn call<E>(
    agent: &ureq::Agent,
    url: &str,
    timeout: Option<Duration>,
) -> Result<(ureq::http::Response<ureq::Body>, Option<String>), Error<E>> {
    let request = agent.get(url);
    let response = match timeout {
        Some(timeout) => request
            .config()
            .timeout_global(Some(timeout))
            .build()
            .call(),
        None => request.call(),
    }
    .map_err(|e| download_error(url, &e))?;
    if response.status() != 200 {
        return Err(Error::Download {
            url: url.to_owned(),
            reason: format!("the server answered {}", response.status()),
        });
    }
    let last_modified = response
        .headers()
        .get("last-modified")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    Ok((response, last_modified))
}

fn download_error<E>(url: &str, error: &impl fmt::Display) -> Error<E> {
    Error::Download {
        url: url.to_owned(),
        reason: error.to_string(),
    }
}

fn cache_error<E>(error: &io::Error) -> Error<E> {
    Error::Cache(error.to_string())
}

/// A file or a directory of the cache that exists only during a download, removed when dropped.
struct Scratch(PathBuf);

impl Scratch {
    /// Removes what a former run may have left there.
    fn clear<E>(&self) -> Result<(), Error<E>> {
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
        let _ = self.clear::<()>();
    }
}
