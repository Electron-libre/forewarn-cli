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
