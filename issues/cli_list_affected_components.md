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
