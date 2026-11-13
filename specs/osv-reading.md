---
id: OSR
status: accepted
adrs: [0001, 0003, 0006]
---

# OSV reading

## Intent

Read vulnerability records in the OSV JSON format, from a file, a directory laid out as an OSV ecosystem archive or,
when the caller opts in, the OSV API, into the vulnerabilities of the domain, so that the matching
(`specs/vulnerability-matching.md`) runs on OSV data.

## Requirements

### Behaviour

- **OSR-1** (deterministic) Reading an OSV record file must return one vulnerability with the id, aliases, source,
  withdrawn state and affected packages of the record.
- **OSR-2** (deterministic) Reading a directory must return the vulnerability of each OSV record file it holds.
- **OSR-3** (deterministic) Reading a file or a directory that holds a record that cannot be read must fail with an
  error that names that file and the cause, from the table of OSR-9.
- **OSR-10** (deterministic) withdrawn: moved to OSF-1 (`specs/osv-fetching.md`).
- **OSR-11** (deterministic) withdrawn: moved to OSF-2 (`specs/osv-fetching.md`).
- **OSR-12** (deterministic) withdrawn: moved to OSF-3 (`specs/osv-fetching.md`).
- **OSR-19** (deterministic) withdrawn: moved to OSF-4 (`specs/osv-fetching.md`).
- **OSR-32** (deterministic) withdrawn: moved to OSF-5 (`specs/osv-fetching.md`).
- **OSR-33** (deterministic) withdrawn: moved to OSF-6 (`specs/osv-fetching.md`).
- **OSR-20** (deterministic) withdrawn: moved to OSF-7 (`specs/osv-fetching.md`).
- **OSR-21** (deterministic) withdrawn: moved to OSF-8 (`specs/osv-fetching.md`).
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

- **OSR-13** (deterministic) withdrawn: moved to OSF-9 (`specs/osv-fetching.md`).
- **OSR-37** (deterministic) withdrawn: replaced by OSF-10 to OSF-13 (`specs/osv-fetching.md`), which tell a damaged snapshot from one that
  cannot be read by the files its download stored.
- **OSR-38** (deterministic) withdrawn: moved to OSF-10 (`specs/osv-fetching.md`).
- **OSR-39** (deterministic) withdrawn: moved to OSF-11 (`specs/osv-fetching.md`).
- **OSR-40** (deterministic) withdrawn: moved to OSF-12 (`specs/osv-fetching.md`).
- **OSR-41** (deterministic) withdrawn: moved to OSF-13 (`specs/osv-fetching.md`).
- **OSR-14** (deterministic) withdrawn: moved to OSF-14 (`specs/osv-fetching.md`).
- **OSR-15** (deterministic) withdrawn: moved to OSF-15 (`specs/osv-fetching.md`).
- **OSR-16** (deterministic) withdrawn: moved to OSF-16 (`specs/osv-fetching.md`).
- **OSR-17** (deterministic) withdrawn: moved to OSF-17 (`specs/osv-fetching.md`).
- **OSR-18** (deterministic) withdrawn: moved to OSF-18 (`specs/osv-fetching.md`).
- **OSR-22** (deterministic) withdrawn: moved to OSF-19 (`specs/osv-fetching.md`).
- **OSR-23** (deterministic) withdrawn: moved to OSF-20 (`specs/osv-fetching.md`).
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

- Fetching the archives OSV publishes per ecosystem into a cache: `specs/osv-fetching.md` says it.
- Querying the OSV API by default: it sends the packages of the inventory out of the CI (ADR 0006); the caller opts
  in.
- Caching the answers of the API, or reading them offline: a query depends on the moment it runs.
- Retrying a failed request, or waiting for a rate limit of the API.
- Listing a record the API does not name for a version: the API decides which records it returns.
- The command-line flags: the CLI wires them.
- The fields the matching does not use (`summary`, `details`, `severity`, `references`, `credits`,
  `database_specific`, `ecosystem_specific`, `published`, `modified`, `related`, `upstream`).
- Validating a record against the OSV JSON schema beyond what reading needs (the format of dates, of versions, of
  ecosystems).
- Merging or deduplicating two records of the same id, or of ids that are aliases of each other.
