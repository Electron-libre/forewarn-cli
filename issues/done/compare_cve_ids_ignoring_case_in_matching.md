---
priority: low
depends_on: [flag_exploited_vulnerabilities]
why: 'only records writing a CVE alias in lower case are affected, and how many OSV records do is not measured'
---
# Compare CVE ids ignoring case in matching, as flagging does

# Goal
Matching takes an id for a CVE only when it starts with an upper-case `CVE-` (VMT-16, VMT-21), while flagging compares
CVE ids ignoring ASCII case (EXF-4). A record written `CVE-2023-1111` with the alias `cve-2023-2222` therefore stays one
match, named `CVE-2023-1111`, and a list naming only `CVE-2023-2222` flags it with the evidence of a CVE that is not
the vulnerability's own; a match carrying two lower-case CVE aliases gets the evidence of the first only. Matching and
flagging should agree on what a CVE id is.

# Findings
* Found by the `high` review of `flag_exploited_vulnerabilities` (2026-11-13), from the code: `matching.rs` tests the
  prefix `CVE-` byte for byte; `exploited.rs` uses `eq_ignore_ascii_case`.
* Measured on 2026-11-13: no id, alias, `related` nor `upstream` entry starting with `CVE-` in another case among the
  294,000 records of the `all.zip` archives of `crates.io`, `Go`, `Maven`, `npm`, `NuGet`, `Packagist`, `PyPI` and
  `RubyGems` (48,600 upper-case ones). The disagreement only reaches local `--osv` records and callers of the domain
  other than the OSV adapter.

# Approach
1. Measure first: count the ids and aliases starting with `cve-` in a few OSV ecosystem archives.
2. Candidates (to pick at step 1 of `issue-workflow`):
   1. Matching reads a CVE id ignoring case and names a match by its upper-case form (amends VMT-16, VMT-17, VMT-21).
   2. The OSV adapter writes a CVE id and alias in upper case when it reads a record (amends `specs/osv-reading.md`).

# Specs
* `specs/vulnerability-matching.md` (VMT-16, VMT-17, VMT-21) or `specs/osv-reading.md`, after the measure.

# Milestone
Flag actively exploited vulnerabilities (KEV, EUVD)

# Resources
* `crates/forewarn-domain/src/matching.rs`: how a match is grouped and named by its CVE.
* `crates/forewarn-domain/src/exploited.rs`: the CVE check of flagging (`is_cve`).
* `specs/exploited-flagging.md`: EXF-4, EXF-9.

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-13

## Understanding
Matching reads an id or alias starting with `CVE-` in any case as the upper-case CVE id (candidate 1, new VMT-29), so
its groups and the name of a match agree with flagging (EXF-4). Out of scope: the full shape of a CVE id (EXF-7), which
matching still reads from the prefix only; the OSV adapter, which keeps the ids as written.

## Plan
1. [x] Matching reads a CVE id ignoring case: `Named` keeps its CVE ids in upper case, the match is named by that
   form and leaves out every CVE alias in any case; verified by the three VMT-29 scenarios in
   `crates/forewarn-domain/tests/matching.rs`; makes true VMT-29. (autonomous)
2. [x] Fixes of the `high` review of the issue: tests of a lower-case CVE as a record id, with VMT-20 and VMT-22;
   the EXF-4/EXF-9 scenario names its match instead of aliasing it; follow-up issue for one CVE id definition;
   verified by `cardinal run project-check`; makes true VMT-29. (autonomous)

## Decisions
- Mode: autonomous
- Base commit: d3494490b07dd2332b3e957b214234e33ae05a36
- Question 1: a (candidate 1, VMT-29).
- Candidate 1 (the domain), not 2 (the OSV adapter): the domain is the rule shared with every caller, and flagging
  already reads a CVE id there.
- The EXF-4 scenario and its test reading a lower-case `cve-` alias of a match named by its `GHSA-` record described
  what matching no longer gives (a `MatchReport` is only built by matching): they now walk the alias to a match named
  `CVE-2021-44228`, then marked.

## Summary of deliverable 1
- done: `Named` reads each id and alias starting with `CVE-` in any case as its upper-case form, for grouping, naming
  and leaving out CVE aliases; spec VMT-29 added (accepted), EXF-4 scenario rewritten, README says the CVE of a match
  is upper case.
- checks: tests 358 passed; clippy, fmt, specs green (`cardinal run project-check`).
- red: VMT-29: `left: [("time", "RUSTSEC-A")] right: [("time", "CVE-2023-1111")]`, and the grouping test reported
  two matches `CVE-2023-1111` and `RUSTSEC-A` for one CVE.
- Code review: no findings (`low`).
- not verified: none.
- decisions needed: none.

## Summary of deliverable 2
- done: three tests of VMT-29 (a record whose id is `cve-…`, a pair not evaluated dropped through a lower-case CVE
  (VMT-20), a record not affecting listed through one (VMT-22)); EXF-4/EXF-9 scenario reworded; issue
  `share_one_definition_of_a_cve_id_in_the_domain` opened, in the milestone.
- `high` review: 6 findings. Fixed: missing tests (3), the EXF scenario of a match aliased by a CVE (5). Follow-up
  issue: the prefix-only `is_cve` of matching against the shape of EXF-7 (1), one CVE id definition for the domain
  (4). Not fixed: a record is listed, and its pair reported, under its id as its source writes it (VMT-18, non-goal
  "each is reported under its record's id") (2); `cves` copying part of `ids` only allocates for a lower-case CVE,
  absent from the archives (6).
- checks: tests 361 passed; clippy, fmt, specs green.
- Code review: no findings (`low`).
- red: none (tests of behaviour deliverable 1 already gives, asked by the review).
- not verified: none.
- decisions needed: none.
