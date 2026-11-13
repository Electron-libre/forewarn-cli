---
priority: low
depends_on: [share_one_definition_of_a_cve_id_in_the_domain]
why: 'two records of the eight archives measured are affected, both in `Packagist`'
---
# Trim the spaces around the ids and aliases of OSV records

# Goal
Some OSV records write an alias with spaces around it. The domain reads a CVE id by its shape (VMT-29, EXF-7), so such
an alias is not read as a CVE id: its record is not grouped with the other records of that CVE, and its match is not
flagged when CISA KEV or EUVD names the CVE. The OSV adapter should read an id or alias without the spaces around it.

# Findings
* Measured on 2026-11-13 over the 293,984 records of the `all.zip` archives of `crates.io`, `Go`, `Maven`, `npm`,
  `NuGet`, `Packagist`, `PyPI` and `RubyGems`: `DRUPAL-CORE-2020-006` aliases `CVE-2020-13665 ` (a trailing space),
  `DRUPAL-CONTRIB-2026-040` aliases ` CVE-2026-49977 ` (a space on each side); no other id or alias starting with
  `CVE-` lacks the shape of EXF-7.
* Not measured: spaces around ids or aliases that do not hold a CVE id, nor in the records of the OSV API.

# Approach
1. Measure first: count the ids and aliases with spaces around them, of any kind, in the same archives.
2. Candidates:
   1. The OSV adapter trims the ASCII whitespace around the id and each alias (amends OSR-1 or its field table).
   2. The domain trims them when it reads an id (VMT-29), for every source.

# Specs
* `specs/osv-reading.md` (OSR-1), or `specs/vulnerability-matching.md` (VMT-29) with candidate 2.

# Milestone
Flag actively exploited vulnerabilities (KEV, EUVD)

# Resources
* `crates/forewarn-osv`: the serde model and its conversion into `Vulnerability`.
* `crates/forewarn-domain/src/cve.rs`: the reading of a CVE id.
* `issues/share_one_definition_of_a_cve_id_in_the_domain.md`: the measure.
