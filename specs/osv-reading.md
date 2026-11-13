---
id: OSR
status: accepted
adrs: [0001, 0003, 0004, 0005, 0006, 0007]
---

# OSV reading

## Intent

Obtain vulnerability records in the OSV JSON format, from a file, a directory laid out as an OSV ecosystem archive,
the archives OSV publishes per ecosystem or, when the caller opts in, the OSV API, and read them into the vulnerabilities of the domain, so that the matching
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
- **OSR-19** (deterministic) A fetch of an ecosystem that another fetch into the same cache is downloading, or is
  putting back the snapshot a stopped fetch left aside, must wait until that fetch is done with the ecosystem, then read its snapshot or download its archive as OSR-13 says.
- **OSR-32** (deterministic) Fetches of an ecosystem into the same cache that each read its cached snapshot without
  downloading must not wait for each other.
- **OSR-33** (deterministic) A fetch that downloads the archive of an ecosystem, or puts back the snapshot a stopped
  fetch left aside, must wait until every other fetch reading the snapshot of that ecosystem in the same cache is done
  with it.
- **OSR-20** (deterministic) Fetches of two different ecosystems into the same cache must not wait for each other.
- **OSR-21** (deterministic) A fetch stopped before it was done with an ecosystem (a killed process) must not make a
  later fetch of that ecosystem wait.
- **OSR-24** (deterministic) Querying the OSV API for a list of packages, each an ecosystem, a name and a version,
  must return the vulnerability of each record the API names for one of them, each id once, in the byte order of the
  ids.
- **OSR-25** (deterministic) Querying must return the freshness of the records: the UTC time the query started and
  the URL of the API.

### Contract

- **OSR-4** (deterministic) Each vulnerability read must carry the fields of this table, taken from the OSV record as
  stated, an absent optional OSV field giving an empty domain field.

  | Domain field | OSV source |
  |---|---|
  | id | `id`, without the whitespace around it (OSR-34) |
  | aliases | `aliases`, in order, each without the whitespace around it (OSR-34), the empty ones dropped (OSR-35) |
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
- **OSR-34** (deterministic) Reading must take the `id` and each alias of a record without the ASCII whitespace
  around it (space, tab, line feed, form feed, carriage return), and read the source from that id; the text inside
  is kept as written.
- **OSR-35** (deterministic) Reading must drop an alias that is empty or holds only ASCII whitespace, so that it
  names no other record.
- **OSR-36** (deterministic) Reading must refuse a record whose `id` is empty or holds only ASCII whitespace, with
  the error "invalid OSV record" of OSR-9, so that unrelated records never share an empty id.
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
  | `id` is absent, not a string, or empty once trimmed (OSR-36), a field of the table of OSR-4 has the wrong type or appears twice, a range `type` is not one of the three, or an event holds none of `introduced`, `fixed`, `last_affected` and `limit` | invalid OSV record, with the parser's reason or the empty `id` |

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
  | another fetch still handles the ecosystem once the wait of OSR-22 is over | cache locked by another run, with the time waited |
  | the server cannot be reached, or answers with a status other than 200 | cannot download, with the URL and the reason or the status |
  | the archive is not a zip archive | not a zip archive, with the reason |
  | an entry of the archive has an absolute name, a name holding `\`, or a name with a `..` component | unsafe archive entry, quoting its name |
  | a record of the archive cannot be read (OSR-9) | the error of OSR-9, naming the entry |
  | the cache directory cannot be read or written | cannot use the cache, with the system's reason |
- **OSR-22** (deterministic) A fetch must wait for another fetch of the same ecosystem (OSR-19) at most the time the
  caller gives, 40 minutes unless the caller gives another, then fail with the error of OSR-18.
- **OSR-23** (deterministic) Fetching under `offline` must read the snapshots of a cache in which it cannot write,
  without waiting for another fetch.
- **OSR-26** (deterministic) A query must send its packages with `POST <api>/v1/querybatch`, a JSON body
  `{"queries": [{"package": {"ecosystem", "name"}, "version"}]}` holding one query per distinct package and version
  in the order of the list, at most 1000 queries per request, `<api>` being `https://api.osv.dev` unless the caller
  gives another.
- **OSR-27** (deterministic) A request to the API must not send any field of a package other than its ecosystem, its
  name and its version.
- **OSR-28** (deterministic) A query whose result carries a `next_page_token` must be sent again with that token as
  its `page_token`, until no result of the query carries one.
- **OSR-29** (deterministic) A query must read the record of each id the results name with one `GET
  <api>/v1/vulns/<id>`, with no body, once per id, through the model of OSR-4.
- **OSR-30** (deterministic) A query of an empty list of packages must send no request.
- **OSR-31** (deterministic) A failed query must fail with the error of this table, the first cause that applies,
  its message quoting the offending value when there is one.

  | Cause | Error |
  |---|---|
  | the API cannot be reached, or answers with a status other than 200 | cannot query the OSV API, with the URL and the reason or the status |
  | an answer of `querybatch` is not JSON, does not hold one result per query with a list of ids, or gives a query a `next_page_token` it already gave that query | invalid OSV API answer, with the reason |
  | an id of a result is empty, starts with `.`, or holds a character other than an ASCII letter, a digit, `.`, `-`, `_` and `:` | invalid record id, quoting it |
  | the record of an id cannot be read (OSR-9), or holds another id | the error of OSR-9, naming the id; invalid OSV record for another id, quoting it |

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
- **OSR-H5** (happy; OSR-19, OSR-13) Given a run fetching `crates.io` into a cache, when a second run fetches
  `crates.io` into it under `if-missing` at the same time, then the second sends no request until the first is done,
  and returns the snapshot the first stored without downloading it again.
- **OSR-H6** (happy; OSR-24, OSR-25, OSR-26, OSR-29) Given an API naming `RUSTSEC-2020-0071` for `crates.io` `time`
  0.1.43, when `time` 0.1.43 and `serde` 1.0.0 are queried, then one `querybatch` request with both packages and one
  request of `/v1/vulns/RUSTSEC-2020-0071` are sent, and that vulnerability is returned with the time of the query and
  the URL of the API.
- (OSR-4) Given a GitHub advisory `GHSA-…` of an npm package, when it is read, then its source is `GHSA`.
- (OSR-4) Given a record with a `last_affected` event, when it is read, then the range carries that event.
- (OSR-5) Given a record with an affected entry holding only `ranges` of type `GIT` and no `package`, when it is
  read, then that entry is skipped and the others are kept.
- (OSR-5) Given a range whose events hold `introduced` `0` and `limit` `2.0.0`, when it is read, then the range has
  the single event introduced `0`.
- (OSR-34) Given a record `DRUPAL-CONTRIB-2026-040` whose aliases are ` CVE-2026-49977 ` and `CVE-2020-13665 `,
  when it is read, then its aliases are `CVE-2026-49977` and `CVE-2020-13665`.
- (OSR-34) Given a record whose `id` is `GHSA-xxxx-yyyy-zzzz` followed by a tab and a line feed, when it is read, then
  its id is `GHSA-xxxx-yyyy-zzzz` and its source `GHSA`.
- (OSR-34) Given an alias `CVE-2026-49977` followed by a no-break space (U+00A0), when it is read, then the no-break
  space is kept: it is not ASCII whitespace.
- (OSR-35) Given a record whose aliases are `CVE-2026-49977`, ` `, an empty alias and a tab, when it is read, then
  its only alias is `CVE-2026-49977`.
- (OSR-36) Given a record whose `id` is empty, or a space and a tab, when it is read, then it fails with "invalid OSV
  record".
- (OSR-36, OSR-3) Given a directory with a valid record and a file `blank.json` whose `id` is a space, when it is
  read, then it fails with "invalid OSV record" naming `blank.json`.
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
- (OSR-32) Given a run reading the snapshot of `crates.io` from a cache, when a second run fetches `crates.io` into
  it under `if-missing` with no wait allowed, then it returns the snapshot without waiting.
- (OSR-33, OSR-22) Given a run reading the snapshot of `crates.io` from a cache, when a second run fetches
  `crates.io` into it under `always`, then it waits, and fails with "cache locked by another run" once its wait is
  over, the cache keeping its snapshot.
- (OSR-33) Given a snapshot of `crates.io` left aside by a stopped run and a run reading the cache, when
  `crates.io` is fetched with a short wait, then it fails with "cache locked by another run".
- (OSR-19, OSR-13) Given a snapshot of `crates.io` older than an age, when two runs fetch it under `older-than` that
  age at the same time, then the archive is downloaded once, the second run reading the snapshot the first stored.
- (OSR-20) Given a run fetching `crates.io` into a cache, when a second run fetches `npm` into it, then the second
  does not wait for the first.
- (OSR-21) Given a run killed while it fetched `crates.io`, when `crates.io` is fetched again, then it does not wait.
- (OSR-22, OSR-18) Given a run fetching `crates.io` for longer than the wait the caller gives, when a second run
  fetches `crates.io`, then it fails with "cache locked by another run" naming `crates.io`, and the cache keeps its
  snapshot.
- (OSR-23) Given a snapshot of `crates.io` in a cache directory the run cannot write in, when `crates.io` is fetched
  under `offline`, then its snapshot is returned.
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

- (OSR-26) Given 1001 distinct packages, when they are queried, then two `querybatch` requests are sent, of 1000
  and 1 queries.
- (OSR-26) Given `time` 0.1.43 listed twice, when it is queried, then the `querybatch` request holds it once.
- (OSR-24, OSR-29) Given an API naming the same id for two packages, when both are queried, then the record is
  requested once and returned once.
- (OSR-28) Given an API answering the first query with a `next_page_token`, when it is queried, then a second
  `querybatch` request holds that query alone with the token as `page_token`, and the ids of both pages are read.
- (OSR-30) Given no package, when it is queried, then no request is sent and no vulnerability is returned.
- (OSR-28, OSR-31) Given an API answering every page of a query with the same `next_page_token`, when it is queried,
  then it fails with "invalid OSV API answer" after two `querybatch` requests.
- (OSR-31) Given an API answering `/v1/vulns/GHSA-a` with the record `RUSTSEC-b`, when it is queried, then it fails
  with "invalid OSV record" naming `GHSA-a` and quoting `RUSTSEC-b`.
- (OSR-31) Given an API answering 503, when it is queried, then it fails with "cannot query the OSV API" quoting the
  status.
- (OSR-31) Given an API answering `querybatch` with a text that is not JSON, when it is queried, then it fails with
  "invalid OSV API answer".
- (OSR-31) Given an API naming the id `../x`, when it is queried, then it fails with "invalid record id" quoting it and
  no request of a record is sent.
- (OSR-31) Given an API answering `/v1/vulns/<id>` with a record whose range `type` is `CALVER`, when it is queried,
  then it fails with "invalid OSV record" naming the id.

## Non-goals

- Querying the OSV API by default: it sends the packages of the inventory out of the CI (ADR 0006); the caller opts
  in.
- Caching the answers of the API, or reading them offline: a query depends on the moment it runs.
- Retrying a failed request, or waiting for a rate limit of the API.
- Listing a record the API does not name for a version: the API decides which records it returns.
- The command-line flags, the default cache directory and the default refresh policy: the CLI wires them.
- Conditional requests (`If-None-Match`, `If-Modified-Since`) and resumed downloads.
- Waiting for a fetch of another machine through a cache on a network file system, where the advisory locks of
  ADR 0005 are not guaranteed.
- Saying that a fetch waits: the caller decides whether to tell the user.
- Serving a waiting download before fetches that start reading after it: reads that keep overlapping can hold it
  back until its wait is over (ADR 0007).
- An `offline` fetch reading a snapshot that a writing fetch replaces at that moment, in a cache it cannot write in.
- Reading a zip archive other than one fetched: a local archive is extracted by the user and read as a directory.
- The fields the matching does not use (`summary`, `details`, `severity`, `references`, `credits`,
  `database_specific`, `ecosystem_specific`, `published`, `modified`, `related`, `upstream`).
- Validating a record against the OSV JSON schema beyond what reading needs (the format of dates, of versions, of
  ecosystems).
- Merging or deduplicating two records of the same id, or of ids that are aliases of each other.
