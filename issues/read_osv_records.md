---
priority: high
depends_on: [match_components_against_vulnerabilities]
why: 'without an OSV adapter the matching has no vulnerabilities to work on'
---
# Read OSV records into domain vulnerabilities

# Goal
A new adapter crate reads vulnerability records in the OSV JSON format into the domain vulnerability types, from local
files, so that the matching can run on OSV data. The OSV types never leave the adapter.

# Approach
1. A crate `forewarn-osv` (commit scope `feeds`), recorded in an ADR next to ADR 0001, that maps the OSV schema to the
   domain types of `match_components_against_vulnerabilities`.
2. Deserialize with `serde` the subset of the schema the domain needs (id, aliases, `affected`, `ranges`, `versions`,
   `modified`), or use an existing OSV crate if its license is compatible with `MIT OR Apache-2.0` and it follows the
   current schema version; measure before choosing.
3. Read one record or a directory of records (the layout of an OSV ecosystem archive), with a clear error naming the
   file of a record that cannot be read.
4. Fixtures: a few real OSV records (a crates.io and an npm advisory with a CVE alias, a withdrawn record, a record
   with `last_affected`).

# Specs
* `specs/osv-reading.md` (to write at step 1): the fields read, the records skipped (withdrawn), the errors.

# Milestone
Match known vulnerabilities (OSV)

# Resources
* `docs/adr/0001-workspace-crate-layout.md`, `docs/adr/0002-parse-cyclonedx-with-cyclonedx-bom.md` (the same choice
  for the CycloneDX adapter).
* OSV schema specification.
* `crates/forewarn/tests/workspace_policy.rs`: a new member must inherit the license and the lints.

# Hints
* A withdrawn record (`withdrawn` set) must not match.
* Keep the record's source (the database prefix of its id, e.g. `GHSA`, `RUSTSEC`) for the report.
