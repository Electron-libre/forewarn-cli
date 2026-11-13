---
priority: medium
depends_on: [group_matches_of_one_vulnerability]
why: 'a wrong merge hides a CVE inside the aliases of another, and later drops the early warning drafted for it'
---
# Keep distinct CVEs in separate matches and say which record affects

# Goal
The grouping of VMT-15 merges the records of one component whose ids or aliases overlap, transitively and whatever
each record says of the component's version. Three gaps remain: two distinct CVEs can end up in one match, a record
that does not affect the component can bridge two groups, and the report does not say which record affects. A match
must stand for one vulnerability, and a reader must see which record makes the component affected.

# Findings
* `high` review of `group_matches_of_one_vulnerability` (2026-11-13), on `crates/forewarn-domain/src/matching.rs`
  (`Group::add`, `Group::into_match`).
* Two CVEs merged: records `RUSTSEC-A` (alias `CVE-1`), `RUSTSEC-B` (alias `CVE-2`) and `GHSA-X` (aliases `CVE-1`,
  `CVE-2`), all covering the component, give one match `CVE-1`; `CVE-2` appears only among its aliases.
* Bridge by a record not affecting: a record fixed before the component's version, aliasing two affected records
  that share no id, merges them and may supply the CVE naming the match.
* VMT-19 lists a mirror fixed before the version among the records of the match, with no mark: a reader checking it
  sees the version fixed and may dismiss a real match.

# Approach
1. Refuse to merge two groups holding different `CVE-` ids; settle where a record aliasing two CVEs goes (into each
   group, or into neither and reported apart).
2. Let only a record that affects the component, or one not evaluated, join or bridge groups; a record not affecting
   joins a group only through an id of its own or an alias it shares with the group, and never supplies its CVE.
3. Mark each record of a match with whether it affects the component (`affects` in the domain `RecordRef`, in the
   JSON `records` and in the human report).

# Specs
* `specs/vulnerability-matching.md`: amends VMT-15, VMT-16, VMT-18, VMT-19; new requirements for 1 and 2.
* `specs/cli-match.md`: amends MCH-1 and MCH-16 for the mark of 3.

# Milestone
Match known vulnerabilities (OSV)

# Resources
* `crates/forewarn-domain/src/matching.rs`, `crates/forewarn/src/report.rs`.
* `issues/done/group_matches_of_one_vulnerability.md` (its `# Tracking`, decisions and deliverable summaries).

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-13

## Understanding
A match stands for one CVE: records holding different `CVE-` ids never share a match, a record holding several goes
into the match of each; a record not affecting the component never joins, bridges or names a match, it is only listed;
each record of a match carries its status (affects, does not, not evaluated). Out of scope: the OSV `related` field.

## Plan
1. [x] Group by CVE: `match_components` builds one group per `CVE-` id held by the records affecting or not evaluated,
   CVE-less records joining each group they overlap, records not affecting only listed in the groups they overlap;
   aliases leave out foreign CVEs and the ids of records of another CVE; pairs not evaluated kept when a CVE of their
   record names no match; verified by domain tests of the new VMT scenarios; makes true VMT-15, VMT-16, VMT-17,
   VMT-19, VMT-20, VMT-21, VMT-22. (autonomous)
2. [x] Record status: `RecordRef.status` (`Affects`, `DoesNotAffect`, `NotEvaluated`) in the domain, `affects`
   (`true`, `false`, `null`) in the JSON `records`, `(does not affect)` / `(not evaluated)` after the record in the
   human report; verified by domain tests and a `forewarn match --osv` test on a RUSTSEC record and a mirror fixed
   earlier; makes true VMT-18, MCH-1, MCH-16. (autonomous)
3. [x] Fixes of the `high` review: copies of one record merged (ids, strongest outcome), records without CVE never
   linked through the id of a record holding a CVE, `affected` computed once per group, doc comments of `Match`;
   verified by `merges_the_copies_of_a_record_given_twice` and
   `never_links_records_without_cve_through_the_id_of_a_record_with_one`; makes true VMT-18, VMT-21. (autonomous)

## Decisions
- Mode: autonomous
- Base commit: e9d6806d5cdf8582d723717889b7d11b68f3a054
- A record holding several `CVE-` ids goes into the match of each (VMT-21).
- JSON `records[].affects`: `true`, `false`, or `null` for a record not evaluated (MCH-16).
- A record not affecting never names a match, its CVE included (VMT-16, VMT-22).

## Deliverable 1: summary
- done: `match_components` builds one group per `CVE-` id of the records affecting or not evaluated, records
  without CVE joining each group they overlap (or forming their own), records not affecting only listed; aliases
  leave out other CVEs and the ids of records of another CVE; a pair not evaluated stays reported when one of its
  CVEs names no match. README and CLAUDE.md say two CVEs are never merged.
- checks: `cardinal run project-check` passes (fmt, clippy, tests, specs).
- red: VMT-16, VMT-17, VMT-19, VMT-20, VMT-21, VMT-22: 7 of 37 domain tests failed, two CVEs in one match
  (`left: [("time", "CVE-1")]`, `right: [("time", "CVE-1"), ("time", "CVE-2")]`).
- Code review: 1 findings (`low`): `named.dedup_by` drops only adjacent duplicates; not fixed, no change needed:
  `naming` returns the places in id order (vulnerabilities sorted by id before indexing), so equal ids are adjacent.
- Decision: VMT-17 leaves out the id of a record of another CVE only among the records affecting or not evaluated, so
  a mirror not affecting stays among the aliases through the affecting record that names it.

## Deliverable 2: summary
- done: `RecordRef.status` (`Affects`, `DoesNotAffect`, `NotEvaluated`); the human report adds `(does not affect)` or
  `(not evaluated)` after a record, the JSON `records` carry `affects` (`true`, `false`, `null`); both specs back to
  `accepted`; README mentions the mark.
- checks: `cardinal run project-check` passes (fmt, clippy, tests, specs).
- red: VMT-18, MCH-1, MCH-16: domain tests did not compile (`struct RecordRef has no field named status`), 3 of 19
  `forewarn match` tests failed (`records` without `affects`).
- Code review: no findings (`low`).

## Deliverable 3: summary
- done: copies of one record merged before grouping (ids united, outcome the strongest); clusters of records without
  CVE linked only through ids no record holding a CVE carries, and joined to a CVE group through its CVE holders
  only; `Group.affected` computed once, pairs derived from the groups; `Match` doc comments follow VMT-16 to VMT-22;
  VMT-21 reworded, two scenarios added.
- checks: `cardinal run project-check` passes (fmt, clippy, tests, specs).
- Code review: no findings (`low`).
- red: VMT-18, VMT-21: `left: []` / `right: [("time", "CVE-1")]` (a later affecting copy dropped), and
  `left: ["GHSA-W", "GHSA-Y", "RUSTSEC-B"]` / `right: ["GHSA-W", "RUSTSEC-B"]` (`GHSA-Y` in the match of `CVE-2`).
- `high` review (7 findings): fixed the dropped copies (2 findings), the cluster leaking into another CVE, the doc
  comments, the repeated `affected` scan and the pairs read back from the matches. Not fixed: the `foreign` set built
  per group (per component, over the records naming its package only).

## Done
- Three deliverables committed; nothing left.
