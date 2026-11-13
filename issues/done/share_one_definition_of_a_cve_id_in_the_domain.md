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
* Measured on 2026-11-13 over the 293,984 records of the `all.zip` archives of `crates.io`, `Go`, `Maven`, `npm`,
  `NuGet`, `Packagist`, `PyPI` and `RubyGems` (48,135 ids and aliases starting with `CVE-`): one alias starts with
  `CVE-` without the shape of EXF-7, `CVE-2020-13665 ` (a trailing space) in `DRUPAL-CORE-2020-006`; a second record,
  `DRUPAL-CONTRIB-2026-040`, writes ` CVE-2026-49977 `, which neither reading takes for a CVE id.
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
* `issues/done/compare_cve_ids_ignoring_case_in_matching.md`: the measure of lower-case CVE ids.

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-13

## Understanding
Matching reads a CVE id as flagging does: the shape of EXF-7, any case, upper-cased; an id starting with `CVE-` without
that shape is a plain id, kept as written. One crate-private module of the domain holds the reading (candidate 1).
Out of scope: a CVE id type (candidate 2), trimming the spaces some OSV aliases carry.

## Plan
1. [x] Shared CVE id: module `cve` of `forewarn-domain` (`is_cve`, `read_id`) used by `matching.rs` and
   `exploited.rs`; the tests of `matching.rs` move from `CVE-1` to shaped ids; verified by new matching tests on
   `CVE-2023-1111-dup`, `cve-pending` and `CVE-2021-123`; makes true VMT-29 (amended). (autonomous)
2. [x] Review fixes of the `high` review: `read_cve` reads a CVE id in one pass for matching and `ExploitedEntry::new`;
   a test fixes that `cve-pending` and `CVE-PENDING` are compared as written; verified by `cargo test`; VMT-29,
   VMT-15. (autonomous)

## Decisions
- Mode: autonomous
- Base commit: 6b8a2e5d0d08e107d3de00f956f7eb9899f1dec1
- 1 a: an issue trims the spaces around OSV aliases in the OSV adapter.
- 2 a: the reading of a CVE id stays `pub(crate)`.

## Deliverable 1
done: module `cve` of the domain (`is_cve` of the shape of EXF-7, `read_id`) used by matching and flagging; VMT-29
amended; the tests and scenarios of VMT move from `CVE-1` to shaped ids.

| check | result |
|---|---|
| tests | `cargo test` green |
| lint | clippy pedantic clean, fmt clean |
| specs | `check-specs` clean for VMT (accepted); pre-existing warning on `cli-match.md` |
| docs | no doc names the reading besides the spec |
| code review | see below |

red: VMT-29, VMT-16, VMT-17: `left: [("time", "CVE-2023-1111"), ("time", "CVE-2023-1111-DUP"), ("time", "CVE-PENDING")] right: [("time", "CVE-2023-1111")]`

Code review: no findings

not verified: none

decisions needed: none

## High review (base..37c5f55)
Code review: 6 findings
1. The alias `CVE-2020-13665 ` is no longer read as a CVE id: not fixed, decision 1 a, issue
   `trim_the_spaces_around_osv_ids_and_aliases`; it was not flaggable before either (its match was named with the space).
2. `cve-pending` and `CVE-PENDING` no longer grouped, untested: fixed, test
   `compares_an_id_starting_with_cve_without_its_shape_as_written`.
3. `is_cve` run twice in flagging: fixed, `read_cve`.
4. `ExploitedEntry::new` upper-cased by hand: fixed, `read_cve`.
5. `is_cve` run twice in `Named::new`: fixed, one pass; the check of `to_match` on the aliases of a group stays.
6. CVE ids read where they are used, not where a `Vulnerability` is built: not fixed, candidate 2 left out of scope.

## Deliverable 2
done: the fixes above.

| check | result |
|---|---|
| tests | `cargo test` green |
| lint | clippy pedantic clean, fmt clean |
| specs | VMT accepted, traced |
| docs | nothing to update |
| code review | see below |

red: none (the test of finding 2 states behaviour of deliverable 1, it passed at once)

Code review: no findings

not verified: none

decisions needed: none
