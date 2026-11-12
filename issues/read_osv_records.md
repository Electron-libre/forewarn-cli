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

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-12

## Understanding
A crate `forewarn-osv` reads one OSV record file, or a flat directory of them (an extracted ecosystem archive), into
`forewarn_domain::vulnerability::Vulnerability`, with errors naming the file. Fetching, zip archives and the CLI are
out of scope. Own `serde` model rather than the `osv` crate (measured: closed ecosystem enum, strict dates; ADR 0003).

## Plan
1. [x] Read one record: crate `forewarn-osv` (workspace member, ADR 0003, spec draft), `serde` model and mapping,
   real fixtures (crates.io and npm advisories with a CVE alias, a withdrawn record, a `last_affected` record);
   verified by tests in `crates/forewarn-osv/tests/`; makes true OSR-1, OSR-4, OSR-5, OSR-6, OSR-8, OSR-9 and OSR-H1. (autonomous)
2. [x] Read a directory: the `.json` files of a directory in file-name order, errors naming the file; verified by
   tests on temp directories; makes true OSR-2, OSR-3, OSR-7 and OSR-H2, spec `accepted`. (autonomous)
3. [ ] Docs and the fixes of the `high` review of the whole issue (CLAUDE.md layout, README, ADR 0003 accepted).

## Decisions
- Mode: autonomous
- Base commit: 80dbb10814b4ce6513fa50be01025b3d7706f38c
- `modified` is not read: a non-goal of the spec, the matching does not use it (answer 1 a).
- A withdrawn record is kept, flagged withdrawn; the domain drops it (VMT-12) (answer 2 a).
- An unknown range `type` refuses the record as invalid (answer 3 a).

## Deliverable 1: read one record
- done: crate `forewarn-osv`, `read_record(path)` maps an OSV record to a domain `Vulnerability`; ADR 0003, spec
  `specs/osv-reading.md` (draft), four real fixtures.
- red: OSR-H1, OSR-1, OSR-4, OSR-5, OSR-6, OSR-8, OSR-9: `unresolved imports forewarn_osv::Cause,
  forewarn_osv::ReadError, forewarn_osv::read_record`.
- Code review: 1 finding: directory reading (OSR-2, OSR-3, OSR-7) is missing; not fixed here, it is deliverable 2.
- not verified: none.
- decisions needed: none.

## Deliverable 2: read a directory
- done: `read_directory(path)` reads the `.json` files of a directory in file-name byte order, errors naming the file;
  spec `accepted`.
- red: OSR-H2, OSR-2, OSR-3, OSR-7, OSR-9: `unresolved import forewarn_osv::read_directory`.
- Code review: no findings.
- not verified: none.
- decisions needed: none.
