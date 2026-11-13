---
id: OSF
status: accepted
adrs: [0004, 0005, 0007, 0008, 0010]
---

# OSV archive fetching

## Intent

Fetch the archive OSV publishes for each ecosystem into a cache under a refresh policy, and read it into the
vulnerabilities of the domain as `specs/osv-reading.md` reads a directory, with the freshness of each download, so
that the matching runs on OSV data with only ecosystem names leaving the CI.

## Requirements

### Behaviour

- **OSF-1** (deterministic) Fetching the records of a list of OSV ecosystems must return the vulnerabilities of the
  archive of each ecosystem, read from the entries at its top as from a directory (OSR-2, OSR-7), the ecosystems in
  the order of the list.
- **OSF-2** (deterministic) Fetching must return, for each ecosystem, the freshness of its records: the UTC time its
  archive was downloaded, the URL it was downloaded from, and the `Last-Modified` header of that download when the
  server sent one.
- **OSF-3** (deterministic) Fetching under the policy `offline` must send no request.
- **OSF-4** (deterministic) A fetch of an ecosystem that another fetch into the same cache is downloading, or is
  putting back the snapshot a stopped fetch left aside, must wait until that fetch is done with the ecosystem, then read its snapshot or download its archive as OSF-9 says.
- **OSF-5** (deterministic) Fetches of an ecosystem into the same cache that each read its cached snapshot without
  downloading must not wait for each other.
- **OSF-6** (deterministic) A fetch that downloads the archive of an ecosystem, or puts back the snapshot a stopped
  fetch left aside, must wait until every other fetch reading the snapshot of that ecosystem in the same cache is done
  with it.
- **OSF-7** (deterministic) Fetches of two different ecosystems into the same cache must not wait for each other.
- **OSF-8** (deterministic) A fetch stopped before it was done with an ecosystem (a killed process) must not make a
  later fetch of that ecosystem wait.

### Contract

- **OSF-9** (deterministic) Fetching must download the archive of an ecosystem only as the refresh policy of this
  table says, and otherwise read the snapshot of its cache directory.

  | Policy | Downloads the archive of an ecosystem |
  |---|---|
  | `offline` | never; an ecosystem with no snapshot fails with "not cached" |
  | `if-missing` | when its cache holds no snapshot of it |
  | `older-than <age>` | when its cache holds no snapshot of it, or one downloaded more than `<age>` ago |
  | `always` | always |

- **OSF-10** (deterministic) A fetch that would read, under `if-missing` or `older-than <age>`, a snapshot whose files
  differ from those its download stored (a file removed, added, or of another size, changed outside forewarn; a file
  whose name starts with `.` is not compared) must
  download the archive again, at most once per fetch, and return what that download returns.
- **OSF-11** (deterministic) A fetch under `offline` of a snapshot whose files differ from those its download stored
  must fail with the error of OSF-18, without a request.
- **OSF-12** (deterministic) A fetch of a snapshot whose files are those its download stored, and whose records cannot
  be read, must fail with the error of reading it (OSF-18), without downloading it again.
- **OSF-13** (deterministic) A snapshot whose record of freshness names no files (stored by an earlier forewarn) must
  be downloaded again under `if-missing` or `older-than <age>`, and read as it is under `offline`.
- **OSF-14** (deterministic) A download must request, with a `GET` and no body, the URL `<base>/<ecosystem>/all.zip`,
  `<base>` being `https://osv-vulnerabilities.storage.googleapis.com` unless the caller gives another.
- **OSF-15** (deterministic) A fetch that reads a snapshot from the cache must return the vulnerabilities and the
  freshness the download that stored it returned.
- **OSF-16** (deterministic) A download that fails, for any cause of OSF-18, must leave the snapshot the cache held
  before unchanged.
- **OSF-17** (deterministic) Fetching must refuse an ecosystem name that is empty, starts with `.`, or holds a
  character other than an ASCII letter, a digit, `.`, `-` and `_`, before any request.
- **OSF-18** (deterministic) A failed fetch must fail with the error of this table, naming the ecosystem, its
  message quoting the offending value when there is one.

  | Cause | Error |
  |---|---|
  | the ecosystem name is refused (OSF-17) | invalid ecosystem name, quoting it |
  | the policy is `offline` and the cache holds no snapshot of the ecosystem | not cached |
  | another fetch still handles the ecosystem once the wait of OSF-19 is over | cache locked by another run, with the time waited |
  | the server cannot be reached, or answers with a status other than 200 | cannot download, with the URL and the reason or the status |
  | the archive is not a zip archive | not a zip archive, with the reason |
  | an entry of the archive has an absolute name, a name holding `\`, or a name with a `..` component | unsafe archive entry, quoting its name |
  | a record of the archive cannot be read (OSR-9) | the error of OSR-9, naming the entry |
  | the policy is `offline` and the files of the snapshot differ from those its download stored (OSF-11) | damaged cached copy, naming the first file that differs and whether it was removed, added or has another size |
  | the cache directory cannot be read or written | cannot use the cache, with the system's reason |
- **OSF-19** (deterministic) A fetch must wait for another fetch of the same ecosystem (OSF-4) at most the time the
  caller gives, 40 minutes unless the caller gives another, then fail with the error of OSF-18.
- **OSF-20** (deterministic) Fetching under `offline` must read the snapshots of a cache in which it cannot write,
  without waiting for another fetch.

## Scenarios

- **OSF-H1** (happy; OSF-1, OSF-2, OSF-9, OSF-14) Given an empty cache and a server publishing a `crates.io`
  archive with a `Last-Modified` header, when `crates.io` and `npm` are fetched under `if-missing`, then
  `<base>/crates.io/all.zip` and `<base>/npm/all.zip` are requested, the vulnerabilities of both archives are
  returned, and each ecosystem carries its download time and URL, `crates.io` its `Last-Modified`.
- **OSF-H2** (happy; OSF-3, OSF-15) Given a cache filled by a fetch of `crates.io`, when `crates.io` is fetched
  under `offline`, then no request is sent and the same vulnerabilities and freshness are returned.
- **OSF-H3** (happy; OSF-4, OSF-9) Given a run fetching `crates.io` into a cache, when a second run fetches
  `crates.io` into it under `if-missing` at the same time, then the second sends no request until the first is done,
  and returns the snapshot the first stored without downloading it again.
- (OSF-9) Given a snapshot downloaded 2 hours ago, when it is fetched under `older-than 1h`, then the archive is
  downloaded again; under `older-than 1d`, it is read from the cache.
- (OSF-9) Given a snapshot in the cache, when it is fetched under `always`, then the archive is downloaded again.
- (OSF-9) Given a snapshot whose record of freshness is damaged, when it is fetched under `if-missing`, then it is
  taken as no snapshot and the archive is downloaded again.
- (OSF-10) Given a snapshot of `crates.io` whose record file `RUSTSEC-2020-0071.json` was removed, or truncated, or
  beside which a file `extra.json` was added, its record of freshness intact, when `crates.io` is fetched under
  `if-missing`, then the archive is downloaded once and its vulnerabilities returned.
- (OSF-10) Given a snapshot beside whose records a hidden file `.DS_Store` was left, when it is fetched under
  `offline`, then its vulnerabilities are returned: a file whose name starts with `.` is not compared.
- (OSF-11) Given the same snapshot, when it is fetched under `offline`, then it fails with "damaged cached copy"
  naming `RUSTSEC-2020-0071.json` (or `extra.json`) and no request is sent.
- (OSF-10, OSF-16) Given a snapshot whose record file was removed and a server answering 503, when it is fetched
  under `if-missing`, then it fails with "cannot download" after one request.
- (OSF-12) Given a snapshot whose record file was overwritten with as many bytes that are not JSON, when it is
  fetched under `if-missing`, then it fails with "not JSON" naming the entry and no request is sent.
- (OSF-12) Given a snapshot whose record file cannot be opened (its permissions removed), when it is fetched under
  `if-missing`, then it fails with the system's reason and no request is sent.
- (OSF-13) Given a snapshot whose record of freshness holds no list of files, when it is fetched under `if-missing`,
  then the archive is downloaded once, and a later fetch reads the new snapshot without a request; under `offline`,
  its vulnerabilities are returned.
- (OSF-16) Given a run stopped after setting the former snapshot aside and before putting the new one in place, when
  the ecosystem is fetched again, then the former snapshot is put back first.
- (OSF-5) Given a run reading the snapshot of `crates.io` from a cache, when a second run fetches `crates.io` into
  it under `if-missing` with no wait allowed, then it returns the snapshot without waiting.
- (OSF-6, OSF-19) Given a run reading the snapshot of `crates.io` from a cache, when a second run fetches
  `crates.io` into it under `always`, then it waits, and fails with "cache locked by another run" once its wait is
  over, the cache keeping its snapshot.
- (OSF-6) Given a snapshot of `crates.io` left aside by a stopped run and a run reading the cache, when
  `crates.io` is fetched with a short wait, then it fails with "cache locked by another run".
- (OSF-4, OSF-9) Given a snapshot of `crates.io` older than an age, when two runs fetch it under `older-than` that
  age at the same time, then the archive is downloaded once, the second run reading the snapshot the first stored.
- (OSF-7) Given a run fetching `crates.io` into a cache, when a second run fetches `npm` into it, then the second
  does not wait for the first.
- (OSF-8) Given a run killed while it fetched `crates.io`, when `crates.io` is fetched again, then it does not wait.
- (OSF-19, OSF-18) Given a run fetching `crates.io` for longer than the wait the caller gives, when a second run
  fetches `crates.io`, then it fails with "cache locked by another run" naming `crates.io`, and the cache keeps its
  snapshot.
- (OSF-20) Given a snapshot of `crates.io` in a cache directory the run cannot write in, when `crates.io` is fetched
  under `offline`, then its snapshot is returned.
- (OSF-9, OSF-18) Given an empty cache, when `npm` is fetched under `offline`, then it fails with "not cached"
  naming `npm`.
- (OSF-16, OSF-18) Given a snapshot of `crates.io` in the cache and a server answering 503, when it is fetched under
  `always`, then it fails with "cannot download" quoting the status, and a fetch under `offline` returns the former
  snapshot.
- (OSF-16, OSF-18) Given a server serving an archive holding a record that is not JSON, when it is fetched, then it
  fails with "not JSON" naming that entry, and the cache keeps its former snapshot.
- (OSF-18) Given a server serving a file that is not a zip archive, when it is fetched, then it fails with "not a zip
  archive".
- (OSF-18) Given an archive holding an entry `../evil.json`, when it is fetched, then it fails with "unsafe archive
  entry" quoting that name, and no file is written outside the cache directory.
- (OSF-17) Given the ecosystem names `../x`, `.hidden` and an empty name, when each is fetched, then each fails with
  "invalid ecosystem name" and no request is sent.
- (OSF-1) Given an archive holding a record in a subdirectory and a `README.txt` beside its records, when it is
  fetched, then only the records at its top are returned.

## Non-goals

- Detecting a record file changed outside forewarn that keeps its size: its record is read as it now is, or fails
  as OSF-12 says (hashing every file at each read costs too much for a large ecosystem).
- The command-line flags, the default cache directory and the default refresh policy: the CLI wires them.
- Conditional requests (`If-None-Match`, `If-Modified-Since`) and resumed downloads.
- Waiting for a fetch of another machine through a cache on a network file system, where the advisory locks of
  ADR 0005 are not guaranteed.
- Saying that a fetch waits: the caller decides whether to tell the user.
- Serving a waiting download before fetches that start reading after it: reads that keep overlapping can hold it
  back until its wait is over (ADR 0007).
- An `offline` fetch reading a snapshot that a writing fetch replaces at that moment, in a cache it cannot write in.
- Reading a zip archive other than one fetched: a local archive is extracted by the user and read as a directory.
- Retrying a failed download.
