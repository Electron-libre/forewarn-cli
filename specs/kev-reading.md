---
id: KEV
status: accepted
adrs: [0004, 0005, 0007, 0008]
---

# CISA KEV catalog reading

## Intent

Give the flagging of exploited vulnerabilities (`specs/exploited-flagging.md`) the CISA Known Exploited
Vulnerabilities catalog, read from a local file or fetched into a cache under a refresh policy, with how fresh it is,
so that a vendor can tell which of its vulnerabilities are actively exploited, also in an air-gapped CI.

## Requirements

### Behaviour

- **KEV-1** (deterministic) Reading a KEV catalog file must return an exploited list named `CISA KEV` holding one
  entry per element of its `vulnerabilities`, each with its `cveID` and its `dateAdded`, in the order of the file.
- **KEV-2** (deterministic) Reading a KEV catalog file must return its freshness: its `catalogVersion` and the date of
  its `dateReleased`.
- **KEV-3** (deterministic) Fetching the catalog must return the list and the freshness that reading the downloaded
  file returns (KEV-1, KEV-2), and the freshness of the download: the UTC time it was downloaded, the URL it was
  downloaded from, and the `Last-Modified` header of that download when the server sent one.
- **KEV-4** (deterministic) Fetching under the policy `offline` must send no request.
- **KEV-5** (deterministic) A fetch of the catalog that another fetch into the same cache is downloading must wait
  until that fetch is done with it, then read its copy or download the catalog as KEV-9 says.
- **KEV-6** (deterministic) Fetches of the catalog into the same cache that each read its cached copy without
  downloading must not wait for each other.
- **KEV-7** (deterministic) A fetch that downloads the catalog must wait until every other fetch reading its cached
  copy in the same cache is done with it.
- **KEV-8** (deterministic) A fetch stopped before it was done with the catalog (a killed process) must not make a
  later fetch wait.

### Contract

- **KEV-9** (deterministic) Fetching must download the catalog only as the refresh policy of this table says, and
  otherwise read the copy of its cache.

  | Policy | Downloads the catalog |
  |---|---|
  | `offline` | never; a cache with no copy fails with "not cached" |
  | `if-missing` | when the cache holds no copy of it |
  | `older-than <age>` | when the cache holds no copy of it, or one downloaded more than `<age>` ago |
  | `always` | always |

- **KEV-18** (deterministic) withdrawn: replaced by KEV-19 to KEV-22, which tell a damaged copy from one that cannot
  be read by the files its download stored.
- **KEV-19** (deterministic) A fetch that would read, under `if-missing` or `older-than <age>`, a cached catalog whose
  files differ from those its download stored (removed, added, or of another size, changed outside forewarn) must
  download it again, at most once per fetch, and return what that download returns.
- **KEV-20** (deterministic) A fetch under `offline` of a cached catalog whose files differ from those its download
  stored must fail with the error of KEV-15, without a request.
- **KEV-21** (deterministic) A fetch of a cached catalog whose files are those its download stored, and that cannot be
  read, must fail with the error of reading it (KEV-15), without downloading it again.
- **KEV-22** (deterministic) A cached catalog whose freshness names no files (stored by an earlier forewarn) must be
  downloaded again under `if-missing` or `older-than <age>`, and read as it is under `offline`.
- **KEV-10** (deterministic) A download must request, with a `GET` and no body, the URL the caller gives,
  `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` unless it gives another.
- **KEV-11** (deterministic) A fetch that reads the catalog from the cache must return the list and both freshnesses
  the download that stored it returned.
- **KEV-12** (deterministic) A download that fails, for any cause of KEV-15, must leave the copy the cache held before
  unchanged.
- **KEV-13** (deterministic) A fetch must wait for another fetch of the catalog (KEV-5, KEV-7) at most the time the
  caller gives, 40 minutes unless the caller gives another, then fail with the error of KEV-15.
- **KEV-14** (deterministic) Fetching under `offline` must read the copy of a cache in which it cannot write, without
  waiting for another fetch.
- **KEV-15** (deterministic) A failed fetch must fail with the error of this table, its message quoting the offending
  value when there is one.

  | Cause | Error |
  |---|---|
  | the policy is `offline` and the cache holds no copy of the catalog | not cached |
  | another fetch still handles the catalog once the wait of KEV-13 is over | cache locked by another run, with the time waited |
  | the server cannot be reached, or answers with a status other than 200 | cannot download, with the URL and the reason or the status |
  | the downloaded catalog cannot be read (KEV-16) | the error of KEV-16 |
  | the policy is `offline` and the files of the copy differ from those its download stored (KEV-20) | damaged cached copy, naming the first file that differs and whether it was removed, added or has another size |
  | the cache directory cannot be read or written | cannot use the cache, with the system's reason |

- **KEV-16** (deterministic) Reading a refused catalog must fail with the error of this table, the first cause that
  applies in table order, naming the file, and the entry by its position (from 0) in `vulnerabilities` when the cause
  is in an entry, its message quoting the offending value when there is one.

  | Cause | Error |
  |---|---|
  | the file cannot be read (an I/O error) | cannot read the input, with the system's reason |
  | the file is not JSON | not JSON |
  | `catalogVersion` or `dateReleased` is absent or not a string, `vulnerabilities` is absent or not a list, an element of it is not an object, or its `cveID` or `dateAdded` is absent or not a string | invalid KEV catalog, with the parser's reason |
  | `dateReleased` does not start with a date `YYYY-MM-DD` of the Gregorian calendar, followed by nothing or by `T` | invalid release date, quoting it |
  | the `cveID` of an entry is not a CVE id (EXF-7) | invalid CVE id, quoting it |
  | the `dateAdded` of an entry is not a date `YYYY-MM-DD` of the Gregorian calendar | invalid date, quoting it |

- **KEV-17** (deterministic) Reading must ignore the members of the catalog and of its entries other than those of
  the table of KEV-16.

## Scenarios

- **KEV-H1** (happy; KEV-1, KEV-2) Given a catalog file of version `2026.11.10`, released
  `2026-11-10T19:03:29.8375Z`, naming `CVE-2021-44228` added on 2021-12-10 and `CVE-2023-4966` added on 2023-10-18,
  when it is read, then the list `CISA KEV` holds both entries in that order, with the version `2026.11.10` and the
  release date 2026-11-10.
- **KEV-H2** (happy; KEV-3, KEV-9, KEV-10) Given an empty cache and a server publishing a catalog, when the catalog is
  fetched under `if-missing`, then it is downloaded once with a `GET` of its URL, and the fetch returns its list, its
  version, its release date, the time of the download, the URL and the `Last-Modified` the server sent.
- **KEV-H3** (happy; KEV-4, KEV-11) Given a cache filled by a fetch, when the catalog is fetched under `offline` with
  no server, then the fetch returns the list and the freshnesses of the first fetch, and no request is sent.
- (KEV-5, KEV-9) Given a run downloading the catalog into a cache, when a second run fetches it under `if-missing`,
  then the second waits, then reads the copy the first stored, without a request.
- (KEV-6) Given a run reading the cached catalog, when a second run fetches it under `if-missing`, then the second
  reads it without waiting.
- (KEV-7, KEV-13) Given a run reading the cached catalog, when a second run fetches it under `always` with a wait
  shorter than the reading, then the second fails with "cache locked by another run".
- (KEV-8) Given a run killed while it fetched the catalog, when the catalog is fetched again, then it does not wait.
- (KEV-9) Given a copy downloaded 2 hours ago, when it is fetched under `older-than 1h`, then the catalog is
  downloaded again; under `older-than 3h`, it is read from the cache.
- (KEV-9) Given a copy in the cache, when it is fetched under `always`, then the catalog is downloaded again.
- (KEV-19) Given a cached catalog file that was removed, or truncated, its freshness intact, when the catalog is
  fetched under `if-missing`, then it is downloaded once and its list returned.
- (KEV-20) Given a cached catalog file that was truncated, when the catalog is fetched under `offline`, then it fails
  with "damaged cached copy" naming the file and no request is sent.
- (KEV-21) Given a cached catalog file overwritten with as many bytes that are not JSON, when the catalog is fetched
  under `if-missing`, then it fails with "not JSON" and no request is sent.
- (KEV-22) Given a copy whose freshness holds no list of files, when the catalog is fetched under `if-missing`, then
  it is downloaded once; under `offline`, its list is returned.
- (KEV-9, KEV-15) Given an empty cache, when the catalog is fetched under `offline`, then it fails with "not cached"
  and no request is sent.
- (KEV-12, KEV-15) Given a copy in the cache and a server answering 503, when it is fetched under `always`, then it
  fails with "cannot download" naming the URL and 503, and a later `offline` fetch returns the former copy.
- (KEV-12, KEV-15) Given a server serving a file that is not JSON, when it is fetched under `always`, then it fails with
  "not JSON", and the former copy stays.
- (KEV-14) Given a copy in a cache directory the run cannot write in, when the catalog is fetched under `offline`, then
  it is read.
- (KEV-16) Given a missing file, when it is read, then it fails with "cannot read the input" naming it.
- (KEV-16) Given a catalog without `vulnerabilities`, or with an entry without `cveID`, when it is read, then it fails
  with "invalid KEV catalog".
- (KEV-16) Given an entry at position 3 whose `cveID` is `CVE-21-44228`, when the catalog is read, then it fails with
  "invalid CVE id" quoting it and naming entry 3.
- (KEV-16) Given an entry whose `dateAdded` is `2023-02-29` or `12/10/2021`, when the catalog is read, then it fails
  with "invalid date" quoting it.
- (KEV-16) Given a `dateReleased` of `2026-13-10T00:00:00Z`, when the catalog is read, then it fails with "invalid
  release date" quoting it; `2026-11-10` alone is accepted.
- (KEV-17) Given a catalog with a member `count` that differs from the number of entries, and entries holding
  `knownRansomwareCampaignUse` and an unknown member, when it is read, then it is read as KEV-1 says.
- (KEV-1) Given a catalog naming the same CVE in two entries, when it is read, then the list holds both entries
  (flagging keeps the earliest date, EXF-6).

## Non-goals

- Flagging the matches (`specs/exploited-flagging.md`), choosing the cache directory, printing the freshness or the
  flag (`specs/cli-match-exploited.md`).
- The EUVD exploited list (`specs/euvd-reading.md`).
- Conditional requests (`If-None-Match`, `If-Modified-Since`): the catalog is a few megabytes.
- Checking `count` against the entries, or keeping the other members of an entry (vendor, product, ransomware use,
  due date): the flagging compares CVE ids only.
- Verifying a signature of the catalog: CISA publishes none beside it.
