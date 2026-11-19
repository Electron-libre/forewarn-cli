//! The cache of the downloads of `forewarn` (ADR 0008): one directory per entry (an OSV ecosystem, the KEV catalog),
//! downloaded again as a refresh policy says (ADR 0004), beside the freshness of its download, and a file lock per
//! entry, shared by the runs that read it and exclusive for the run that replaces it (ADRs 0005, 0007). What a
//! download holds and how it is read is the source's: it hands [`Cache::fetch`] two functions. The freshness of a
//! download records the name and the size of each file it stored, checked before the copy is read (ADR 0010).

use std::collections::{BTreeMap, BTreeSet};
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

/// What the file [`FRESHNESS_FILE`] holds: the freshness of the download, and the size of each file it stored by name
/// (ADR 0010); none in a file an earlier forewarn wrote.
#[derive(Serialize, Deserialize)]
struct Record {
    #[serde(flatten)]
    freshness: Freshness,
    #[serde(default)]
    files: Option<Files>,
}

/// The size of each file of an entry directory, by name, but its freshness and the hidden files a system tool may
/// leave there (`.DS_Store`), which no source reads.
type Files = BTreeMap<String, u64>;

/// How a file of a cached copy differs from what its download stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    /// The download stored it; the copy no longer holds it.
    Removed,
    /// The copy holds it; the download did not store it.
    Added,
    /// The copy holds it with another size than the download stored (truncated, or changed).
    Resized { stored: u64, found: u64 },
}

/// The first file, by name, of a cached copy that differs from what its download stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Damage {
    pub file: String,
    pub change: Change,
}

impl fmt::Display for Damage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "damaged cached copy: \"{}\" ", self.file)?;
        match self.change {
            Change::Removed => write!(f, "was removed"),
            Change::Added => write!(f, "was added"),
            Change::Resized { stored, found } => {
                write!(f, "has another size: {found} bytes, {stored} downloaded")
            }
        }
    }
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
    /// The server cannot be reached or does not answer 200; `status` is the status it answered, if it answered.
    Download {
        url: String,
        reason: String,
        status: Option<u16>,
    },
    /// The cache directory cannot be read or written; the system's reason.
    Cache(String),
    /// The policy is [`Refresh::Offline`] and the files of the cached copy differ from those its download stored.
    Damaged(Damage),
    /// The source could not unpack or read the download, or read the entry.
    Source(E),
}

impl<E: fmt::Display> fmt::Display for Error<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotCached => write!(f, "not cached, and the refresh policy is offline"),
            Self::Locked { waited } => write!(f, "cache locked by another run, waited {waited:?}"),
            Self::Download { url, reason, .. } => write!(f, "cannot download {url}: {reason}"),
            Self::Cache(reason) => write!(f, "cannot use the cache: {reason}"),
            Self::Damaged(damage) => write!(f, "{damage}"),
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
    /// starts. A copy whose files differ from those its download stored (changed outside forewarn) is downloaded again,
    /// once, unless the policy is [`Refresh::Offline`]; a copy whose freshness names no files (written by an earlier
    /// forewarn) is downloaded again, or read as it is under [`Refresh::Offline`] (ADR 0010).
    ///
    /// # Errors
    ///
    /// The [`Error`] that stops the fetch; a failed download leaves the copy the cache held before unchanged. A `name`
    /// that is empty, starts with `.` (the scratch paths of the cache do), or holds a character other than an ASCII
    /// letter, a digit, `.`, `-`, `_` and `%` fails with [`Error::Cache`] before the cache is touched.
    pub fn fetch<T, E>(
        &self,
        agent: &ureq::Agent,
        name: &str,
        source: &Source<'_, T, E>,
        clock: &impl Fn() -> SystemTime,
    ) -> Result<Fetched<T>, Error<E>> {
        if !is_entry_name(name) {
            return Err(Error::Cache(format!("invalid entry name \"{name}\"")));
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
        // The freshness of a copy whose files differ from its download under the shared lock (damaged outside
        // forewarn): the fetch then downloads it under the exclusive lock, one download at most.
        let mut damaged = None;
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
                (Some((freshness, files)), Mode::Shared) => {
                    match check(&directory, files.as_ref())? {
                        None => return read(source, &directory, freshness),
                        Some(damage) if self.refresh == Refresh::Offline => {
                            return Err(Error::Damaged(damage));
                        }
                        Some(_) => damaged = Some(freshness),
                    }
                }
                // The copy found damaged, unchanged since.
                (Some((freshness, _)), Mode::Exclusive) if damaged.as_ref() == Some(&freshness) => {
                    break;
                }
                // Another run replaced the damaged copy while this one waited for the exclusive lock.
                (Some((freshness, files)), Mode::Exclusive) if damaged.is_some() => {
                    if check(&directory, files.as_ref())?.is_none() {
                        return read(source, &directory, freshness);
                    }
                    break;
                }
                (None, Mode::Exclusive) => break,
                // A download, or putting the copy back, waits for every other run. Another run may have downloaded
                // while this one waited for the exclusive lock: it then reads the copy under the shared lock, beside
                // the other readers.
                (None, Mode::Shared) | (Some(_), Mode::Exclusive) => {}
            }
            if let Some(file) = &lock {
                file.unlock().map_err(|e| cache_error(&e))?;
            }
            mode = match mode {
                Mode::Shared => Mode::Exclusive,
                Mode::Exclusive => Mode::Shared,
            };
        }
        let download = Download {
            agent,
            file: Scratch(scratch("download")),
            staging: Scratch(scratch("staging")),
            former: Scratch(former),
        };
        download.run(source, &directory, clock())
    }

    /// The freshness of the copy of a directory, and the files its download stored, when the refresh policy reads it
    /// rather than downloading it again; `clock` is read only by a policy that compares with the time. Only
    /// [`Refresh::Offline`] reads a copy whose freshness names no files (ADR 0010).
    fn cached<E>(
        &self,
        directory: &Path,
        clock: &impl Fn() -> SystemTime,
    ) -> Result<Option<(Freshness, Option<Files>)>, Error<E>> {
        Ok(match (self.refresh, read_record(directory)?) {
            (Refresh::Offline, None) => return Err(Error::NotCached),
            (Refresh::Offline, Some(record)) => Some((record.freshness, record.files)),
            (_, Some(Record { files: None, .. })) => None,
            (Refresh::IfMissing, Some(record)) => Some((record.freshness, record.files)),
            // A copy dated after now (a clock set back) is not older than any age.
            (Refresh::OlderThan(age), Some(record))
                if clock()
                    .duration_since(record.freshness.downloaded_at)
                    .map_or(true, |elapsed| elapsed <= age) =>
            {
                Some((record.freshness, record.files))
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
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'%'))
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
        let record = Record {
            freshness: Freshness {
                downloaded_at: now,
                url: source.url.clone(),
                last_modified,
            },
            files: Some(list_files(&self.staging.0)?),
        };
        let json = serde_json::to_vec(&record).map_err(|e| Error::Cache(e.to_string()))?;
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
        Ok(Fetched {
            value,
            freshness: record.freshness,
        })
    }
}

/// Reads a cached copy whose files are those its download stored; an error of the source is its own, never damage.
fn read<T, E>(
    source: &Source<'_, T, E>,
    directory: &Path,
    freshness: Freshness,
) -> Result<Fetched<T>, Error<E>> {
    let value = (source.read)(directory).map_err(Error::Source)?;
    Ok(Fetched { value, freshness })
}

/// The first file, by name, of a directory that differs from the files its download stored; none when they are the
/// same, or when its freshness names no files.
fn check<E>(directory: &Path, stored: Option<&Files>) -> Result<Option<Damage>, Error<E>> {
    let Some(stored) = stored else {
        return Ok(None);
    };
    let found = list_files(directory)?;
    if *stored == found {
        return Ok(None);
    }
    let names: BTreeSet<&String> = stored.keys().chain(found.keys()).collect();
    Ok(names.into_iter().find_map(|name| {
        let change = match (stored.get(name), found.get(name)) {
            (Some(_), None) => Change::Removed,
            (None, Some(_)) => Change::Added,
            (Some(&stored), Some(&found)) if stored != found => Change::Resized { stored, found },
            _ => return None,
        };
        Some(Damage {
            file: name.clone(),
            change,
        })
    }))
}

/// The size of each file of a directory, by name, but its freshness and its hidden files.
fn list_files<E>(directory: &Path) -> Result<Files, Error<E>> {
    let mut files = Files::new();
    for entry in fs::read_dir(directory).map_err(|e| cache_error(&e))? {
        let entry = entry.map_err(|e| cache_error(&e))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name != FRESHNESS_FILE && !name.starts_with('.') {
            let size = entry.metadata().map_err(|e| cache_error(&e))?.len();
            files.insert(name, size);
        }
    }
    Ok(files)
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

/// The record of the copy of a directory; none when the directory holds no copy, or one whose freshness cannot be
/// read (a later download replaces it).
fn read_record<E>(directory: &Path) -> Result<Option<Record>, Error<E>> {
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
            status: Some(response.status().as_u16()),
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
        status: None,
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
