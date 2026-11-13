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
* Not measured: how many records of the OSV archives write a CVE id or alias in lower case.

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
