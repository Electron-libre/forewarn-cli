---
id: OSR
status: draft
adrs: [0001, 0003]
---

# OSV reading

## Intent

Read vulnerability records in the OSV JSON format, one file or a directory laid out as an OSV ecosystem archive, into
the vulnerabilities of the domain, so that the matching (`specs/vulnerability-matching.md`) runs on OSV data.

## Requirements

### Behaviour

- **OSR-1** (deterministic) Reading an OSV record file must return one vulnerability with the id, aliases, source,
  withdrawn state and affected packages of the record.
- **OSR-2** (deterministic) Reading a directory must return the vulnerability of each OSV record file it holds.
- **OSR-3** (deterministic) Reading a file or a directory that holds a record that cannot be read must fail with an
  error that names that file and the cause, from the table of OSR-9.

### Contract

- **OSR-4** (deterministic) Each vulnerability read must carry the fields of this table, taken from the OSV record as
  stated, an absent optional OSV field giving an empty domain field.

  | Domain field | OSV source |
  |---|---|
  | id | `id` |
  | aliases | `aliases`, in order |
  | source | the database prefix of `id`: the text before its first `-` (`RUSTSEC`, `GHSA`), or the whole `id` when it has none |
  | withdrawn | set when `withdrawn` is present |
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
  | `id` is absent or not a string, a field of the table of OSR-4 has the wrong type, or a range `type` is not one of the three | invalid OSV record, with the parser's reason |

## Scenarios

- **OSR-H1** (happy; OSR-1, OSR-4) Given the crates.io advisory `RUSTSEC-2020-0071` of `time`, when it is read, then
  the vulnerability has that id, the alias `CVE-2020-26235`, the source `RUSTSEC`, and the package `crates.io`
  `time` with its `SEMVER` ranges.
- **OSR-H2** (happy; OSR-2, OSR-7) Given a directory holding a crates.io and an npm advisory and a `README.txt`, when
  it is read, then both vulnerabilities are returned, in the order of their file names, and the text file is ignored.
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
- (OSR-3, OSR-9) Given a directory with a valid record and a file `broken.json` that is not JSON, when it is read,
  then it fails with "not JSON" naming `broken.json`.
- (OSR-2) Given an empty directory, when it is read, then no vulnerability is returned.
- (OSR-9) Given a path that does not exist, when it is read, then it fails with "cannot read the input" naming it.

## Non-goals

- Fetching records, from the OSV API or the archives: `issues/fetch_osv_records.md`.
- Reading a zip archive: the directory is the archive extracted.
- The fields the matching does not use (`summary`, `details`, `severity`, `references`, `credits`,
  `database_specific`, `ecosystem_specific`, `published`, `modified`, `related`, `upstream`).
- Validating a record against the OSV JSON schema beyond what reading needs (the format of dates, of versions, of
  ecosystems).
- Merging or deduplicating two records of the same id, or of ids that are aliases of each other.
