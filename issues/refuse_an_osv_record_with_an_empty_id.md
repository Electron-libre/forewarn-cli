---
priority: low
depends_on: [trim_the_spaces_around_osv_ids_and_aliases]
why: 'no record of the eight archives measured has an empty id or one of whitespace only'
---
# Refuse or skip an OSV record whose id is empty

# Goal
Reading an OSV record accepts an `id` that is empty, or, since OSR-34 trims it, one of whitespace only: the
vulnerability gets the id `""` and the source `""`. Every such record shares that id, so the domain groups them
(VMT-21) into one match named `""`, from unrelated records. The OSV adapter should not give the domain an empty id.

# Findings
* Found by the `high` review of `issues/done/trim_the_spaces_around_osv_ids_and_aliases.md`.
* An `id` of `""` was already accepted before OSR-34; an `id` of `" "` was read as `" "`, now as `""`.
* The OSV API path already refuses an empty id named by `querybatch` (OSR-31, "invalid record id").
* Measured on 2026-11-13 over the 293,984 records of the `all.zip` archives of `crates.io`, `Go`, `Maven`, `npm`,
  `NuGet`, `Packagist`, `PyPI` and `RubyGems`: no id has whitespace around it; empty ids not counted.

# Approach
1. Measure first: count the empty ids in the same archives.
2. Candidates:
   1. Add an empty id (after OSR-34) to the "invalid OSV record" cause of OSR-9: a single such record then fails the
      read of a whole directory or archive (OSR-3).
   2. Skip such a record when reading a directory or an archive, failing only a single file read.

# Specs
* `specs/osv-reading.md` (OSR-9, OSR-34, or a new requirement).

# Milestone
Flag actively exploited vulnerabilities (KEV, EUVD)

# Resources
* `crates/forewarn-osv/src/lib.rs`: `parse_record`, `From<Record> for Vulnerability`.
* `crates/forewarn-domain/src/matching.rs`: the grouping of records by shared ids.

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-13

## Understanding
Refuse an OSV record whose `id` is empty once trimmed (OSR-34) as an "invalid OSV record" (candidate 1), so that the
domain never groups unrelated records under `""`. Out of scope: skipping such a record in a directory or an archive.

## Plan
1. [x] Refuse an empty id: `parse_record` fails with "invalid OSV record" when the trimmed `id` is empty; verified by
   `reading.rs` (a file, a directory); makes true OSR-36. (autonomous)

## Measure
2026-11-13, the `all.zip` archives of `crates.io`, `Go`, `Maven`, `npm`, `NuGet`, `Packagist`, `PyPI`, `RubyGems`:
293,958 records, none with an `id` absent, empty or of whitespace only. Refusing such a record (candidate 1) fails no
read of today's archives; skipping it (candidate 2) would hide a broken feed.

## Decisions
- Mode: autonomous
- Base commit: ccc1de0e128dce1f699dbc162a27d291d1f9dfb8
- Answer 1 a: refuse the record (candidate 1).

## Deliverable 1
done: `parse_record` refuses a record whose `id` is empty once trimmed with "invalid OSV record: `id` is empty";
OSR-36 added to `specs/osv-reading.md` and to the cause of OSR-9, the spec accepted.

| check | result |
|---|---|
| tests | pass |
| lint | pass |
| specs | pass |
| docs | spec only; no other page describes the refusals of the OSV reading |
| code review | pass |

red: OSR-36: `the record is refused: Vulnerability { id: "", aliases: [], source: "", withdrawn: false, affected: [] }`

Code review: no findings

not verified: none. decisions needed: none.
