---
priority: low
depends_on: [compare_cve_ids_ignoring_case_in_matching]
why: 'only an id starting with `CVE-` but not shaped as one is affected, and no OSV archive measured writes one in lower case'
---
# Share one definition of a CVE id in the domain

# Goal
Matching reads an id or alias as a CVE when it starts with `CVE-` in any ASCII case (VMT-29), while flagging takes
only an id of the shape of EXF-7 (`CVE-`, a year of four digits, `-`, four digits or more). An alias such as
`cve-pending` or `CVE-2021-44228-dup` therefore makes a match of its own, named by it, that flagging can never flag,
and is left out of the aliases of the match of its record. The domain should hold one definition of a CVE id, used by
both.

# Findings
* Found by the `high` review of `compare_cve_ids_ignoring_case_in_matching` (2026-11-13), from the code: `is_cve` of
  `matching.rs` tests the prefix only; `is_cve` of `exploited.rs` tests the shape of EXF-7.
* `Vulnerability.aliases` keeps each id as its source writes it: each new reader of the domain (the early warning
  draft, other callers of the crate) has to read a CVE id again.
* Not measured: how many ids or aliases of the OSV archives start with `CVE-` without the shape of EXF-7.
* Many tests of `crates/forewarn-domain/tests/matching.rs` use `CVE-1`, `CVE-2` as CVE ids: with the shape of EXF-7,
  they would need ids of that shape.

# Approach
1. Measure first: count the ids and aliases of a few OSV ecosystem archives that start with `CVE-` in any case without
   the shape of EXF-7.
2. Candidates:
   1. One crate-level function reading a CVE id (the shape of EXF-7, any case, upper-case form), used by matching and
      flagging (amends VMT-29).
   2. A type of the domain for a CVE id, built where a `Vulnerability` is built, so that its ids carry it.

# Specs
* `specs/vulnerability-matching.md` (VMT-29), `specs/exploited-flagging.md` (EXF-7).

# Milestone
Flag actively exploited vulnerabilities (KEV, EUVD)

# Resources
* `crates/forewarn-domain/src/matching.rs`: `is_cve`, `read_id`, `Named`.
* `crates/forewarn-domain/src/exploited.rs`: `is_cve`, `ExploitedEntry::new`.
* `issues/compare_cve_ids_ignoring_case_in_matching.md`: the measure of lower-case CVE ids.
