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
* Found by the `high` review of `issues/refuse_an_osv_record_with_an_empty_id.md`.
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
