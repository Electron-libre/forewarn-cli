---
priority: medium
depends_on: [cli_list_affected_components]
why: 'a real SBOM against the npm or PyPI archive tests every component against every record, which takes minutes'
---
# Match large archives without testing every component against every record

# Goal
`forewarn match` gives the matching every record of every ecosystem archive it fetched. The matching tests every
component against every record, so a large SBOM against a large archive (npm holds hundreds of thousands of records)
does on the order of 10^8 comparisons. A run must take time in proportion to the components and the records that
name them.

# Findings
* `forewarn_domain::matching::match_components` loops over the components, then over every vulnerability
  (high review of `cli_list_affected_components`, 2026-11-13). Nothing has been measured yet.
* The clean count of MCH-3 (`crates/forewarn/src/report.rs`, `clean_count`) compares each component with every match
  and every result not evaluated.

# Approach
1. Measure first: time `forewarn match --osv` with an SBOM of a few thousand npm components against an extracted npm
   archive.
2. In the domain, index the affected packages by ecosystem and name (normalized as VMT-6 says) before the loop, so
   that a component meets only the records that name its package. The order of VMT-13 and the results stay the same.
3. Count the clean components from component indexes rather than by comparing values; consider moving the count to
   the domain beside the matching.

# Specs
* None expected: the results of `specs/vulnerability-matching.md` and `specs/cli-match.md` stay the same.

# Milestone
Match known vulnerabilities (OSV)

# Resources
* `crates/forewarn-domain/src/matching.rs`, `crates/forewarn/src/report.rs`, `specs/vulnerability-matching.md`.
