---
id: MCH
status: draft
adrs: [0001, 0004]
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
  vulnerability's id, aliases and source.
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

### Contract

- **MCH-10** (deterministic) The command must exit with the code of this table, the first row that applies.

  | Situation | Exit code |
  |---|---|
  | the arguments are invalid (unknown option, unknown format or refresh policy, `--osv` with `--cache`, `--refresh` or `--osv-url`, no SBOM given, no cache directory MCH-12 can find) | 2 |
  | the SBOM cannot be read (any error of SBR-7) | 3 |
  | the OSV records cannot be read (OSR-9) or fetched (OSR-18) | 5 |
  | the report cannot be written to standard output, a closed pipe aside (MCH-20) | 4 |
  | a component is affected, without `--allow-affected` | 1 |
  | no component is affected, or one is with `--allow-affected` | 0 |

- **MCH-11** (deterministic) `--refresh` must accept `offline`, `if-missing`, `always`, and an age written as a
  positive whole number followed by `m`, `h` or `d` (minutes, hours, days), which means `older-than <age>` (OSR-13),
  and default to `1d`.
- **MCH-12** (deterministic) The cache directory must be `--cache <dir>` when given, else `$XDG_CACHE_HOME/forewarn/osv`
  when `XDG_CACHE_HOME` is set and not empty, else `$HOME/.cache/forewarn/osv` when `HOME` is set and not empty.
- **MCH-13** (deterministic) The archives must be downloaded from `--osv-url <url>` when given, else from the OSV
  bucket of OSR-14.
- **MCH-14** (deterministic) An SBOM or OSV records that cannot be read or fetched must print nothing on standard
  output and one line on standard error naming the path of the SBOM (`standard input` for `-`), the file or the
  ecosystem, and the error of SBR-7, OSR-9 or OSR-18.
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
  | `osv` | an array, in the order of MCH-5 or of the `--osv` paths, of objects `{"kind": "archive", "ecosystem", "url", "downloadedAt", "lastModified"}` (`downloadedAt` in RFC 3339, UTC, to the second, ending in `Z`; `lastModified` a string or `null`) or `{"kind": "local", "path"}` |
  | `affected` | an array, in the order of VMT-13, of objects `name`, `version` (string or `null`), `purl` (string or `null`), `id`, `aliases` (an array of strings), `source` |
  | `notEvaluated` | an array, in the order of VMT-13, of objects `name`, `version`, `purl` (as in `affected`), `reason` (one of `"no package URL"`, `"invalid package URL"`, `"unknown ecosystem"`, `"no version"`, `"range not evaluated"`, `"invalid version"`), `vulnerabilityId` (the id of the pair, or `null` for a component reason) |

- **MCH-17** (deterministic) `--format` must accept `human`, the default, and `json`.
- **MCH-18** (deterministic) The human report must print each control character of a value read from the SBOM or the
  OSV records escaped (`\n`, `\u{1b}`), as CHK-14 does.
- **MCH-19** (deterministic) `forewarn` with no subcommand must print its usage naming `match` beside `check`.

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

## Non-goals

- The exact layout of the human report beyond what MCH-1 to MCH-4 state: scripts read the JSON report.
- The completeness check: `forewarn check` prints it; both commands can run in one CI job.
- Failing on a component not evaluated: it is printed, never counted clean, but does not change the exit code.
- Showing the progress of a download.
- Grouping the records of one vulnerability known under several ids (`issues/group_matches_of_one_vulnerability.md`).
- Querying the OSV API (`issues/query_the_osv_api.md`).
- Severity, exploitation status, deadlines and draft early warnings: later milestones.
