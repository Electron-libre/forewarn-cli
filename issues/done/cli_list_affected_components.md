---
priority: high
depends_on: [match_components_against_vulnerabilities, fetch_osv_records]
why: 'the milestone goal is the list of affected components, which only the CLI shows'
---
# List the affected components from the command line

# Goal
`forewarn` must print the components of an SBOM affected by known vulnerabilities, each with the vulnerability id,
its aliases (CVE) and its source, as text and as JSON, with an exit code a CI job can act on.

# Approach
1. Settle at step 1 whether the list goes into `forewarn check` (one command for the whole report) or into a new
   subcommand, and how its exit code combines with the completeness one of CHK-7.
2. Print the components not evaluated (no purl, no version, an ecosystem whose ranges are not compared yet) apart from
   the clean ones, so that a gap is never read as "no vulnerability".
3. Print the freshness of the OSV data used.
4. End-to-end tests on a fixture SBOM and local OSV records, without the network.

# Specs
* `specs/cli-check.md` (amended) or a new CLI spec (to write at step 1): the output, the JSON members, the exit codes.

# Milestone
Match known vulnerabilities (OSV)

# Resources
* `specs/cli-check.md`, `crates/forewarn/src/main.rs`, `crates/forewarn/src/report.rs`.
* `crates/forewarn/tests/check.rs`: the end-to-end tests of `check`.

# Hints
* Report formats live in the `report` module of the CLI crate (an adapter), not in the domain.

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-13

## Understanding
A new subcommand `forewarn match <sbom>` (planned by the non-goals of CHK) prints the matches, the components and
pairs not evaluated and the clean count, with the freshness of the OSV data, as text or JSON; `check` is unchanged and
the two exit codes stay apart. Records come from local `--osv` paths or from the cached OSV archives of the
ecosystems the SBOM uses. Out of scope: grouping aliases, the OSV API, KEV/EUVD.

## Plan
1. [x] `forewarn match --osv <path>`: the subcommand on local records, human and JSON report, exit codes, escaping;
   verified by end-to-end tests on a fixture SBOM and the OSV fixtures; makes true MCH-1 to MCH-3, MCH-4 (local),
   MCH-6 to MCH-10, MCH-14 to MCH-20 (~900 lines). (autonomous)
2. [x] Fetch the archives: ecosystems derived from the SBOM, `--cache` and its default, `--refresh`, `--osv-url`, the
   freshness of each archive (RFC 3339 through `time`); verified by end-to-end tests against a loopback server and an
   `offline` cache; makes true MCH-4 (archives), MCH-5, MCH-11 to MCH-13, sets the spec `accepted` (~700 lines). (autonomous)
3. [x] Docs of the whole issue (README usage and exit codes, CLAUDE.md status) and the fixes of the `high` review;
   makes true MCH-21 to MCH-23, MCH-12 amended. (autonomous)

## Decisions
- Mode: autonomous
- Base commit: 67dd4b428b4ad03625c5d5ac8d3219213b26d669
- A new subcommand `forewarn match`, not an option of `check`: `check` stays offline and keeps its exit code.
- Exit 1 when a component is affected, 0 with `--allow-affected`; a component not evaluated never changes the exit code.
- Default refresh policy `older-than 1d`; default cache `$XDG_CACHE_HOME/forewarn/osv`, else `$HOME/.cache/forewarn/osv`, else exit 2.
- `--osv-url` is a documented option (internal mirror, loopback in tests).

## Deliverable 1 summary
- done: `forewarn match --osv <path>…` on local records, human and JSON reports, exit codes 1/3/4/5, test helpers
  shared in `tests/common`; README, CLAUDE.md and the non-goal of CHK updated.
- red: MCH-H1, MCH-1, MCH-2, MCH-3, MCH-4, MCH-6, MCH-7, MCH-10, MCH-15: `error: unrecognized subcommand 'match'`
- Code review: 1 findings: the `OSV records: none` branch is unreachable while `--osv` is required; kept, deliverable 2
  reaches it (an SBOM with no ecosystem fetches nothing).
- not verified: `--osv` given without fetching is required until deliverable 2 (no default source yet).

## Deliverable 2 summary
- done: without `--osv`, `forewarn match` fetches the archive of each ecosystem of the SBOM into `--cache` (default
  under `XDG_CACHE_HOME` or `HOME`) under `--refresh` (default `1d`) from `--osv-url`, and reports the freshness of
  each archive; `--osv` excludes the three options; spec `accepted`; README and CLAUDE.md updated.
- red: MCH-H2, MCH-4, MCH-5, MCH-8, MCH-9, MCH-13, MCH-16: `error: unexpected argument '--cache' found`
- Code review: 1 findings: `--refresh 1é` panicked on a byte split; fixed (split on the last character), cases added.
- not verified: a download from the real OSV bucket (MCH-13 is proven by an internal test, without the network).

## Deliverable 3 summary
- done: the docs were updated with each deliverable; fixes of the `high` review: a record id read twice is matched
  once (MCH-21), each source shows its record count (MCH-22), error lines escaped (MCH-23), a relative
  `XDG_CACHE_HOME` ignored (MCH-12), the missing-cache error shows the usage of `forewarn match`, a damaged download
  time prints `unknown` instead of panicking, `run_match` simplified.
- red: MCH-12, MCH-14, MCH-21, MCH-22, MCH-23: the record counted twice, `local records` without a count, the error on
  two lines, the cache under the working directory.
- Code review (high): 10 findings: 8 fixed as above; the concurrent use of the shared cache and the cross product of the
  matching filed as `issues/done/lock_the_osv_cache_against_concurrent_runs.md` and
  `issues/done/match_large_archives_without_the_cross_product.md` (the clean count goes with the latter, which may move it
  to the domain).
- Code review (low): no findings.
- not verified: the `unknown` download time (a damaged cache file) has no test.
