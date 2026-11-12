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
