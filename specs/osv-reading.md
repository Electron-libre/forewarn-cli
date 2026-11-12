---
id: OSR
status: accepted
adrs: [0001, 0003, 0004]
---

# OSV reading

## Intent

Obtain vulnerability records in the OSV JSON format, from a file, a directory laid out as an OSV ecosystem archive or
the archives OSV publishes per ecosystem, and read them into the vulnerabilities of the domain, so that the matching
(`specs/vulnerability-matching.md`) runs on OSV data.

## Requirements

### Behaviour

- **OSR-1** (deterministic) Reading an OSV record file must return one vulnerability with the id, aliases, source,
  withdrawn state and affected packages of the record.
- **OSR-2** (deterministic) Reading a directory must return the vulnerability of each OSV record file it holds.
- **OSR-3** (deterministic) Reading a file or a directory that holds a record that cannot be read must fail with an
  error that names that file and the cause, from the table of OSR-9.
- **OSR-10** (deterministic) Fetching the records of a list of OSV ecosystems must return the vulnerabilities of the
  archive of each ecosystem, read from the entries at its top as from a directory (OSR-2, OSR-7), the ecosystems in
  the order of the list.
- **OSR-11** (deterministic) Fetching must return, for each ecosystem, the freshness of its records: the UTC time its
  archive was downloaded, the URL it was downloaded from, and the `Last-Modified` header of that download when the
  server sent one.
- **OSR-12** (deterministic) Fetching under the policy `offline` must send no request.

### Contract

- **OSR-4** (deterministic) Each vulnerability read must carry the fields of this table, taken from the OSV record as
  stated, an absent optional OSV field giving an empty domain field.

  | Domain field | OSV source |
  |---|---|
  | id | `id` |
  | aliases | `aliases`, in order |
  | source | the database prefix of `id`: the text before its first `-` (`RUSTSEC`, `GHSA`), or the whole `id` when it has none or that text is empty |
  | withdrawn | set when `withdrawn` is present and not `null` |
  | affected packages | each entry of `affected` that has a `package`, in order |
  | ecosystem of a package | `package.ecosystem`, as written |
  | name of a package | `package.name`, as written |
  | versions of a package | `versions`, in order |
  | ranges of a package | each entry of `ranges`, in order: its `type` (`SEMVER`, `ECOSYSTEM`, `GIT`) and its events in order |
  | events of a range | each entry of `events` holding `introduced`, `fixed` or `last_affected`, with its version |

- **OSR-5** (deterministic) Reading must skip, without failing, an entry of `affected` with no `package`, an event
  holding only `limit`, and every field of the record the table of OSR-4 does not name.
- **OSR-6** (deterministic) Reading must keep a withdrawn record, flagged withdrawn, so that the matching drops it
  (VMT-12).
- **OSR-7** (deterministic) Reading a directory must read only the files of that directory whose name ends in
  `.json`, not its subdirectories, and return their vulnerabilities in the byte order of the file names.
- **OSR-8** (deterministic) Reading must refuse a record whose `schema_version` is present with a major version other
  than `1`.
- **OSR-9** (deterministic) A refused input must fail with the error of this table, the first cause that applies in
  table order, naming the file, its message quoting the offending value when there is one.

  | Cause | Error |
  |---|---|
  | the file or the directory cannot be read (an I/O error) | cannot read the input, with the system's reason |
  | the file is not JSON | not JSON |
  | `schema_version` names a major version other than 1 | unsupported schema version, quoting it |
  | `id` is absent or not a string, a field of the table of OSR-4 has the wrong type or appears twice, a range `type` is not one of the three, or an event holds none of `introduced`, `fixed`, `last_affected` and `limit` | invalid OSV record, with the parser's reason |

- **OSR-13** (deterministic) Fetching must download the archive of an ecosystem only as the refresh policy of this
  table says, and otherwise read the snapshot of its cache directory.

  | Policy | Downloads the archive of an ecosystem |
  |---|---|
  | `offline` | never; an ecosystem with no snapshot fails with "not cached" |
  | `if-missing` | when its cache holds no snapshot of it |
  | `older-than <age>` | when its cache holds no snapshot of it, or one downloaded more than `<age>` ago |
  | `always` | always |

- **OSR-14** (deterministic) A download must request, with a `GET` and no body, the URL `<base>/<ecosystem>/all.zip`,
  `<base>` being `https://osv-vulnerabilities.storage.googleapis.com` unless the caller gives another.
- **OSR-15** (deterministic) A fetch that reads a snapshot from the cache must return the vulnerabilities and the
  freshness the download that stored it returned.
- **OSR-16** (deterministic) A download that fails, for any cause of OSR-18, must leave the snapshot the cache held
  before unchanged.
- **OSR-17** (deterministic) Fetching must refuse an ecosystem name that is empty, starts with `.`, or holds a
  character other than an ASCII letter, a digit, `.`, `-` and `_`, before any request.
- **OSR-18** (deterministic) A failed fetch must fail with the error of this table, naming the ecosystem, its
  message quoting the offending value when there is one.

  | Cause | Error |
  |---|---|
  | the ecosystem name is refused (OSR-17) | invalid ecosystem name, quoting it |
  | the policy is `offline` and the cache holds no snapshot of the ecosystem | not cached |
  | the server cannot be reached, or answers with a status other than 200 | cannot download, with the URL and the reason or the status |
  | the archive is not a zip archive | not a zip archive, with the reason |
  | an entry of the archive has an absolute name, a name holding `\`, or a name with a `..` component | unsafe archive entry, quoting its name |
  | a record of the archive cannot be read (OSR-9) | the error of OSR-9, naming the entry |
  | the cache directory cannot be read or written | cannot use the cache, with the system's reason |

## Scenarios

- **OSR-H1** (happy; OSR-1, OSR-4) Given the crates.io advisory `RUSTSEC-2020-0071` of `time`, when it is read, then
  the vulnerability has that id, the alias `CVE-2020-26235`, the source `RUSTSEC`, and the package `crates.io`
  `time` with its `SEMVER` ranges.
- **OSR-H2** (happy; OSR-2, OSR-7) Given a directory holding a crates.io and an npm advisory and a `README.txt`, when
  it is read, then both vulnerabilities are returned, in the order of their file names, and the text file is ignored.
- **OSR-H3** (happy; OSR-10, OSR-11, OSR-13, OSR-14) Given an empty cache and a server publishing a `crates.io`
  archive with a `Last-Modified` header, when `crates.io` and `npm` are fetched under `if-missing`, then
  `<base>/crates.io/all.zip` and `<base>/npm/all.zip` are requested, the vulnerabilities of both archives are
  returned, and each ecosystem carries its download time and URL, `crates.io` its `Last-Modified`.
- **OSR-H4** (happy; OSR-12, OSR-15) Given a cache filled by a fetch of `crates.io`, when `crates.io` is fetched
  under `offline`, then no request is sent and the same vulnerabilities and freshness are returned.
- (OSR-4) Given a GitHub advisory `GHSA-…` of an npm package, when it is read, then its source is `GHSA`.
- (OSR-4) Given a record with a `last_affected` event, when it is read, then the range carries that event.
- (OSR-5) Given a record with an affected entry holding only `ranges` of type `GIT` and no `package`, when it is
  read, then that entry is skipped and the others are kept.
- (OSR-5) Given a range whose events hold `introduced` `0` and `limit` `2.0.0`, when it is read, then the range has
  the single event introduced `0`.
- (OSR-6) Given a withdrawn record, when it is read, then it is returned flagged withdrawn.
- (OSR-8, OSR-9) Given a record with `schema_version` `2.0.0`, when it is read, then it fails with "unsupported
  schema version" quoting `2.0.0`; with `1.7.4`, it is read.
- (OSR-9) Given a record whose range `type` is `CALVER`, when it is read, then it fails with "invalid OSV record".
- (OSR-9) Given a range whose events hold `introduced` `0` and `fixed_in` `1.2.0`, when it is read, then it fails with
  "invalid OSV record", rather than read as a range open to every version.
- (OSR-5, OSR-8) Given a record whose `schema_version` is the number `1` and whose `limit` event is a number, when it
  is read, then it is read.
- (OSR-3) Given a directory holding a symbolic link `GHSA-x.json` to a file that does not exist, when it is read, then
  it fails with "cannot read the input" naming `GHSA-x.json`.
- (OSR-3, OSR-9) Given a directory with a valid record and a file `broken.json` that is not JSON, when it is read,
  then it fails with "not JSON" naming `broken.json`.
- (OSR-2) Given an empty directory, when it is read, then no vulnerability is returned.
- (OSR-9) Given a path that does not exist, when it is read, then it fails with "cannot read the input" naming it.
- (OSR-13) Given a snapshot downloaded 2 hours ago, when it is fetched under `older-than 1h`, then the archive is
  downloaded again; under `older-than 1d`, it is read from the cache.
- (OSR-13) Given a snapshot in the cache, when it is fetched under `always`, then the archive is downloaded again.
- (OSR-13) Given a snapshot whose record of freshness is damaged, when it is fetched under `if-missing`, then it is
  taken as no snapshot and the archive is downloaded again.
- (OSR-16) Given a run stopped after setting the former snapshot aside and before putting the new one in place, when
  the ecosystem is fetched again, then the former snapshot is put back first.
- (OSR-13, OSR-18) Given an empty cache, when `npm` is fetched under `offline`, then it fails with "not cached"
  naming `npm`.
- (OSR-16, OSR-18) Given a snapshot of `crates.io` in the cache and a server answering 503, when it is fetched under
  `always`, then it fails with "cannot download" quoting the status, and a fetch under `offline` returns the former
  snapshot.
- (OSR-16, OSR-18) Given a server serving an archive holding a record that is not JSON, when it is fetched, then it
  fails with "not JSON" naming that entry, and the cache keeps its former snapshot.
- (OSR-18) Given a server serving a file that is not a zip archive, when it is fetched, then it fails with "not a zip
  archive".
- (OSR-18) Given an archive holding an entry `../evil.json`, when it is fetched, then it fails with "unsafe archive
  entry" quoting that name, and no file is written outside the cache directory.
- (OSR-17) Given the ecosystem names `../x`, `.hidden` and an empty name, when each is fetched, then each fails with
  "invalid ecosystem name" and no request is sent.
- (OSR-10) Given an archive holding a record in a subdirectory and a `README.txt` beside its records, when it is
  fetched, then only the records at its top are returned.

## Non-goals

- Querying the OSV API (`/v1/querybatch`, `/v1/vulns/<id>`): it sends the package URLs of the inventory out of the
  CI; the archives send only ecosystem names.
- The command-line flags, the default cache directory and the default refresh policy: the CLI wires them.
- Conditional requests (`If-None-Match`, `If-Modified-Since`) and resumed downloads.
- Sharing one cache between runs that fetch the same ecosystem at the same time.
- Reading a zip archive other than one fetched: a local archive is extracted by the user and read as a directory.
- The fields the matching does not use (`summary`, `details`, `severity`, `references`, `credits`,
  `database_specific`, `ecosystem_specific`, `published`, `modified`, `related`, `upstream`).
- Validating a record against the OSV JSON schema beyond what reading needs (the format of dates, of versions, of
  ecosystems).
- Merging or deduplicating two records of the same id, or of ids that are aliases of each other.
