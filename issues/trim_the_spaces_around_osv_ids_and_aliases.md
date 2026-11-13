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
* `issues/done/share_one_definition_of_a_cve_id_in_the_domain.md`: the measure.

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-13

## Understanding
The OSV adapter reads the `id` and each alias of a record without the ASCII whitespace around them (candidate 1), the
source taken from the trimmed id, so the domain reads ` CVE-2026-49977 ` as a CVE id. Applies to files, archives and
the OSV API, which share the parsing. Out of scope: the domain (candidate 2), `related`/`upstream` (not read).

## Plan
1. [x] Trim the id and aliases in the OSV adapter: `From<Record> for Vulnerability` trims them; verified by tests of
   `crates/forewarn-osv/tests/reading.rs` on the two scenarios of OSR-34; makes true OSR-34. (autonomous)

## Measure
2026-11-13, the `all.zip` archives of `crates.io`, `Go`, `Maven`, `npm`, `NuGet`, `Packagist`, `PyPI`, `RubyGems`:
293,984 records, 293,984 ids, 122,697 aliases, 4,867 `related`. Only two values have whitespace around them, both
aliases with ASCII spaces: `CVE-2020-13665 ` (`DRUPAL-CORE-2020-006`), ` CVE-2026-49977 ` (`DRUPAL-CONTRIB-2026-040`).
No id, alias or `related` holds whitespace inside.

## Decisions
- Mode: autonomous
- Base commit: 96c81188715676cd14af6fd42abd559ac9df5448

## Deliverable 1
done: `From<Record> for Vulnerability` trims the ASCII whitespace around the id and each alias (`str::trim_ascii`),
the source read from the trimmed id; OSR-34 added, `specs/osv-reading.md` accepted.

| check | result |
|---|---|
| tests | pass |
| lint | pass |
| specs | pass |
| docs | spec only; no other page describes the reading of ids and aliases |
| code review | pass |

red: OSR-34: `left: [" CVE-2026-49977 ", "CVE-2020-13665 "]` / `right: ["CVE-2026-49977", "CVE-2020-13665"]`, and
`left: "\u{c} GHSA-xxxx-yyyy-zzzz\t\n\r"` / `right: "GHSA-xxxx-yyyy-zzzz"`

Code review: no findings

not verified: a `forewarn match` run on the Packagist archive flagging `DRUPAL-CONTRIB-2026-040` (the domain is
covered by its own tests).

decisions needed: none
