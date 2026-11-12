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
2. [ ] Fetch the archives: ecosystems derived from the SBOM, `--cache` and its default, `--refresh`, `--osv-url`, the
   freshness of each archive (RFC 3339 through `time`); verified by end-to-end tests against a loopback server and an
   `offline` cache; makes true MCH-4 (archives), MCH-5, MCH-11 to MCH-13, sets the spec `accepted` (~700 lines).
3. [ ] Docs of the whole issue (README usage and exit codes, CLAUDE.md status) and the fixes of the `high` review.

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
