---
id: MCH
status: accepted
adrs: [0001, 0004, 0006]
---

# The `forewarn match` command

## Intent

Let a vendor, at a terminal or in a CI job, list in one command the components of a CycloneDX SBOM affected by known
OSV vulnerabilities, apart from the components that could not be evaluated, with the freshness of the data used and an
exit code a CI job can act on.

## Requirements

### Behaviour

- **MCH-1** (deterministic) `forewarn match <sbom>` must print each match of the matching
  (`specs/vulnerability-matching.md`): the component's name, its version and package URL when it has them, and the
  vulnerability's id, aliases, and the id, source and status of each of its records (VMT-18), the status shown for a
  record that does not affect the component or could not be evaluated.
- **MCH-2** (deterministic) `forewarn match <sbom>` must print each component or pair not evaluated (VMT-3) with its
  reason, under a heading of its own, apart from the matches and from the count of clean components.
- **MCH-3** (deterministic) `forewarn match <sbom>` must print how many components were matched and how many are
  clean: neither affected nor named by a component or pair not evaluated.
- **MCH-4** (deterministic) `forewarn match <sbom>` must print the freshness of each source of OSV records it used:
  for a fetched ecosystem its name, the UTC time its archive was downloaded, its URL, and its `Last-Modified` when the
  server sent one (OSR-11); for a local path given with `--osv`, that path.
- **MCH-5** (deterministic) Without `--osv`, `forewarn match <sbom>` must fetch the OSV archive (OSR-10) of each OSV
  ecosystem a component maps to (VMT-4), each once, in the order of the first component that maps to it, and fetch
  nothing when no component maps to one.
- **MCH-6** (deterministic) `forewarn match --osv <path> <sbom>` must match against the records of that OSV record file
  or directory (OSR-1, OSR-2), repeated for several paths, and send no request.
- **MCH-7** (deterministic) `forewarn match -` must read the SBOM from standard input.
- **MCH-8** (deterministic) `forewarn match --format json <sbom>` must print the same result as one JSON document.
- **MCH-9** (deterministic) `forewarn match --allow-affected <sbom>` must exit with the code of an SBOM with no match
  when a component is affected, the report printed unchanged.
- **MCH-24** (deterministic) `forewarn match --osv-api <sbom>` must query the OSV API (OSR-24) for the OSV ecosystem,
  name and version of each component that maps to one (VMT-4), the version of a Go component without its leading `v`,
  match against the records it returns, and fetch no archive.
- **MCH-25** (deterministic) `forewarn match` without `--osv-api` must send no request to the OSV API.
- **MCH-26** (deterministic) `forewarn match --osv-api <sbom>` must print the OSV API as its source of records, with
  its URL, the UTC time of the query and the number of records read (OSR-25).

### Contract

- **MCH-10** (deterministic) The command must exit with the code of this table, the first row that applies.

  | Situation | Exit code |
  |---|---|
  | the arguments are invalid (unknown option, unknown format or refresh policy, `--osv` with `--cache`, `--refresh`, `--osv-url` or `--osv-api`, `--osv-api` with `--cache`, `--refresh` or `--osv-url`, `--osv-api-url` without `--osv-api`, no SBOM given, no cache directory MCH-12 can find without `--osv` nor `--osv-api`) | 2 |
  | the SBOM cannot be read (any error of SBR-7) | 3 |
  | the OSV records cannot be read (OSR-9), fetched (OSR-18) or queried (OSR-31) | 5 |
  | the report cannot be written to standard output, a closed pipe aside (MCH-20) | 4 |
  | a component is affected, without `--allow-affected` | 1 |
  | no component is affected, or one is with `--allow-affected` | 0 |

- **MCH-11** (deterministic) `--refresh` must accept `offline`, `if-missing`, `always`, and an age written as a
  positive whole number followed by `m`, `h` or `d` (minutes, hours, days), which means `older-than <age>` (OSR-13),
  and default to `1d`.
- **MCH-12** (deterministic) The cache directory must be `--cache <dir>` when given, else `$XDG_CACHE_HOME/forewarn/osv`
  when `XDG_CACHE_HOME` is an absolute path, else `$HOME/.cache/forewarn/osv` when `HOME` is set and not empty.
- **MCH-13** (deterministic) The archives must be downloaded from `--osv-url <url>` when given, else from the OSV
  bucket of OSR-14.
- **MCH-14** (deterministic) An SBOM or OSV records that cannot be read, fetched or queried must print nothing on
  standard output and one line on standard error naming the path of the SBOM (`standard input` for `-`), the file,
  the ecosystem or the OSV API, and the error of SBR-7, OSR-9, OSR-18 or OSR-31.
- **MCH-15** (deterministic) The report, in either format, must be printed on standard output and nothing else on
  standard error.
- **MCH-20** (deterministic) A report that cannot be written to standard output must print one line on standard error
  naming the cause, unless standard output is a closed pipe.
- **MCH-16** (deterministic) The JSON report must be one object with the members of this table.

  | Member | Value |
  |---|---|
  | `specVersion` | the spec version of the SBOM, a string (`"1.6"`) |
  | `componentCount` | the number of components matched, nested ones included |
  | `cleanCount` | the number of clean components (MCH-3) |
  | `osv` | an array, in the order of MCH-5 or of the `--osv` paths, of objects `{"kind": "archive", "ecosystem", "url", "downloadedAt", "lastModified", "recordCount"}` (`downloadedAt` in RFC 3339, UTC, to the second, ending in `Z`; `lastModified` a string or `null`), `{"kind": "api", "url", "queriedAt", "recordCount"}` (`queriedAt` as `downloadedAt`) or `{"kind": "local", "path", "recordCount"}` (`recordCount` the number of MCH-22) |
  | `affected` | an array, in the order of VMT-13, of objects `name`, `version` (string or `null`), `purl` (string or `null`), `id`, `aliases` (an array of strings), `records` (an array of objects `{"id", "source", "affects"}`, in the order of VMT-18, `affects` being `true`, `false`, or `null` for a record not evaluated) |
  | `notEvaluated` | an array, in the order of VMT-13, of objects `name`, `version`, `purl` (as in `affected`), `reason` (one of `"no package URL"`, `"invalid package URL"`, `"unknown ecosystem"`, `"no version"`, `"range not evaluated"`, `"invalid version"`), `vulnerabilityId` (the id of the pair, or `null` for a component reason) |

- **MCH-17** (deterministic) `--format` must accept `human`, the default, and `json`.
- **MCH-18** (deterministic) The human report must print each control character of a value read from the SBOM or the
  OSV records escaped (`\n`, `\u{1b}`), as CHK-14 does.
- **MCH-19** (deterministic) `forewarn` with no subcommand must print its usage naming `match` beside `check`.
- **MCH-21** (deterministic) A record whose id was already read, from another archive or another `--osv` path, must
  not be matched again, so that a component is reported once per vulnerability id.
- **MCH-27** (deterministic) The OSV API must be queried at `--osv-api-url <url>` when given, else at the URL of
  OSR-26.
- **MCH-28** (deterministic) `forewarn match --help` must say that `--osv-api` sends the OSV ecosystem, name and
  version of each component to the OSV API.
- **MCH-22** (deterministic) Each source of MCH-4 must be printed with the number of records read from it, so that a
  source holding none is never read as "no vulnerability".
- **MCH-23** (deterministic) The line of an error on standard error must print each control character of a value read
  from the SBOM, the OSV records, an archive or the server escaped, as MCH-18 does.

## Scenarios

- **MCH-H1** (happy; MCH-1, MCH-2, MCH-3, MCH-4, MCH-6, MCH-10) Given an SBOM with `pkg:cargo/time@0.1.43`, a component
  without a package URL and a clean component, and a directory of OSV records holding `RUSTSEC-2020-0071`, when the
  vendor runs `forewarn match --osv records/ sbom.json`, then they see the directory as the source, `time` 0.1.43
  with `RUSTSEC-2020-0071`, `CVE-2020-26235` and `RUSTSEC`, the component without a package URL as not evaluated,
  1 clean component of 3, and the command exits with 1.
- **MCH-H2** (happy; MCH-4, MCH-5, MCH-8, MCH-9, MCH-13, MCH-16) Given a CI job with an empty cache and an OSV mirror
  serving the `crates.io` archive with a `Last-Modified` header, when it runs
  `forewarn match --format json --allow-affected --cache cache/ --osv-url <mirror> sbom.json` on an SBOM of crates,
  then only `<mirror>/crates.io/all.zip` is requested, the JSON report lists the affected crates and the archive with
  its download time, URL and `Last-Modified`, and the command exits with 0.
- **MCH-H3** (happy; MCH-24, MCH-26, MCH-27) Given an OSV API mirror naming `RUSTSEC-2020-0071` for `time` 0.1.43, when
  the vendor runs `forewarn match --osv-api --osv-api-url <mirror> sbom.json` on an SBOM of crates, then one
  `querybatch` request names the crates, `time` 0.1.43 is listed with `RUSTSEC-2020-0071`, the report gives the API
  with the time of the query, and the command exits with 1.
- (MCH-5, MCH-11) Given a cache filled by a previous run, when `forewarn match --refresh offline` runs on the same
  SBOM, then no request is sent and the report gives the download time of the previous run.
- (MCH-5) Given an SBOM whose components have no package URL, when it is matched without `--osv`, then no request is
  sent, the source list is empty, and every component is reported not evaluated.
- (MCH-10, MCH-14) Given an empty cache and `--refresh offline`, when an SBOM of crates is matched, then standard error
  names `crates.io` and "not cached", and the command exits with 5.
- (MCH-10, MCH-14) Given `--osv` naming a directory holding a record that is not JSON, when the SBOM is matched, then
  standard error names that file and "not JSON", and the command exits with 5.
- (MCH-10) Given an SBOM that cannot be read and an empty cache, when it is matched, then the command exits with 3 and
  sends no request.
- (MCH-10, MCH-11) Given `--refresh 0d`, `--refresh 2w` or `--refresh soon`, when the command runs, then it exits
  with 2.
- (MCH-10, MCH-12) Given neither `--cache`, `XDG_CACHE_HOME` nor `HOME`, when the command runs without `--osv`, then
  it exits with 2; with `--osv`, it runs.
- (MCH-10) Given `--osv` and `--refresh always`, when the command runs, then it exits with 2.
- (MCH-2, MCH-16) Given a `PyPI` component and a record naming it with only an `ECOSYSTEM` range, when it is matched,
  then it is reported not evaluated with `range not evaluated` and the record's id, and is not counted clean.
- (MCH-3, MCH-10) Given an SBOM no record affects, when it is matched, then every evaluated component is clean and
  the command exits with 0.
- (MCH-18) Given a record whose id holds an escape sequence, when the human report prints it, then `\u{1b}` is
  written out.
- (MCH-12) Given `XDG_CACHE_HOME=.cache`, a relative path, when the command runs, then the cache is under
  `$HOME/.cache`.
- (MCH-21) Given the same record in a directory and given again as a file, when the SBOM is matched, then the
  component it affects is reported once.
- (MCH-22) Given `--osv` naming a directory whose records are all in subdirectories, when the SBOM is matched, then the
  source shows 0 records.
- (MCH-1, MCH-16) Given a directory holding `RUSTSEC-2020-0071` and its `GHSA` mirror, both affecting `time` 0.1.43,
  when the SBOM is matched, then `time` is listed once as `CVE-2020-26235`, with both records and their sources.
- (MCH-1, MCH-16) Given a directory holding `RUSTSEC-2020-0071` affecting `time` 0.1.43 and its `GHSA` mirror fixed at
  0.1.40, when the SBOM is matched, then the human report marks the mirror as not affecting `time` and the JSON report
  gives it `"affects": false`.
- (MCH-24) Given a component `pkg:golang/github.com/x/y@v1.2.3`, when it is matched with `--osv-api`, then the
  `querybatch` request names the `Go` package `github.com/x/y` at version `1.2.3`.
- (MCH-24) Given an SBOM whose components have no package URL, when it is matched with `--osv-api`, then no request
  is sent and the source shows the API with 0 records.
- (MCH-10, MCH-12, MCH-24) Given neither `--cache`, `XDG_CACHE_HOME` nor `HOME`, when the command runs with
  `--osv-api`, then it runs.
- (MCH-10) Given `--osv-api` with `--osv`, `--refresh always` or `--osv-url`, or `--osv-api-url` alone, when the
  command runs, then it exits with 2.
- (MCH-10, MCH-14) Given an OSV API answering 503, when the SBOM is matched with `--osv-api`, then standard error
  names the API and "cannot query the OSV API", and the command exits with 5.
- (MCH-23) Given a directory holding a file that is not JSON and whose name holds a newline, when it is read, then the
  error stays on one line.

## Non-goals

- The exact layout of the human report beyond what MCH-1 to MCH-4 state: scripts read the JSON report.
- The completeness check: `forewarn check` prints it; both commands can run in one CI job.
- Failing on a component not evaluated: it is printed, never counted clean, but does not change the exit code.
- Showing the progress of a download.
- An environment variable that turns on `--osv-api`: sending the inventory out stays a choice made on the command line.
- Severity, exploitation status, deadlines and draft early warnings: later milestones.
