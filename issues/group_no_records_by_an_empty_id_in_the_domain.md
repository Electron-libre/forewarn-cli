---
priority: low
depends_on: [refuse_an_osv_record_with_an_empty_id]
why: 'the only adapter that builds vulnerabilities today, OSV, already refuses an empty id (OSR-36)'
---
# Group no records by an empty or blank id in the domain

# Goal
The domain groups the records that name each other (VMT-21) by every id and alias as given. Two unrelated
vulnerabilities whose id or an alias is empty, or of whitespace only, share that value and are grouped into one
match. The OSV adapter refuses an empty id (OSR-36) and drops an empty alias (OSR-35), but `Vulnerability` has public
fields and the domain is meant to be reused by other callers (the hosted service, a future feed adapter): the
grouping should not depend on each adapter's guard.

# Findings
* Found by the `high` review of `issues/done/refuse_an_osv_record_with_an_empty_id.md`.
* `Named::new` in `crates/forewarn-domain/src/matching.rs` inserts `record.id` and each alias into its `ids` as given.

# Approach
1. Leave out an empty or blank id or alias from the ids a record is grouped by, in `Named::new`.
2. Decide what a match whose record has an empty id is named (VMT-16) and whether such a record is matched at all.

# Specs
* `specs/vulnerability-matching.md` (VMT-21, VMT-16, or a new requirement).

# Milestone
Flag actively exploited vulnerabilities (KEV, EUVD)

# Resources
* `crates/forewarn-domain/src/matching.rs`: `Named::new`, the grouping of records.
* `specs/osv-reading.md`: OSR-35, OSR-36.

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-13

## Understanding
The domain leaves blank ids and aliases out of the grouping, naming and aliases of a match, and never takes two
records with a blank id for copies of one record (VMT-30). Out of scope: the adapters (OSR-35, OSR-36 already hold).

## Plan
1. [x] Blank ids in the matching: `Named::new` drops blank ids and aliases, the copy dedup skips blank record ids,
   VMT-16 falls back to the aliases when no member has a non-blank id; verified by tests in
   `crates/forewarn-domain/tests/matching.rs` (the VMT-30 scenarios); makes true VMT-30 (spec back to `accepted`). (autonomous)

## Decisions
- Mode: autonomous
- Base commit: a595113ee4e32567422cb8d0becb44b81cfc3267
- A record with a blank id and no other id nor alias is matched, its match named by its id as given (VMT-30), not
  reported as a pair not evaluated.

## Deliverable 1
- done: `Named::new` leaves blank ids and aliases out, the copy dedup never merges two blank record ids, a match with
  no CVE falls back to its first other id, then to its blank record id; VMT-30 added, spec back to `accepted`.
- red: VMT-30, VMT-15, VMT-16, VMT-17: `left: [("time", ""), ("time", "RUSTSEC-A")]` against four matches;
  `left: [" ", "  ", "GHSA-X"]` against `["GHSA-X"]`; `left: [("time", "")]` against `[("time", "GHSA-X")]`.
- docs: n/a, README and CLAUDE.md say nothing blank ids change.
- checks: project-check ok (fmt, clippy, tests, specs), size 90 lines.
- Code review: no findings
- not verified: none. decisions needed: none.
