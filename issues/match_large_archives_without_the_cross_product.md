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

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-13

## Understanding
`forewarn match` must run in time proportional to the components and the records naming them, not to their product.
No behaviour changes (VMT and MCH results identical, no spec amended); the clean count stays in `report.rs`, by a
hash set of the components reported rather than a domain move.

## Plan
1. [x] Measure, then index the vulnerabilities by ecosystem and normalized name (VMT-6) in `match_components`, each
   component meeting only the records naming its package, in id order so the groups and VMT-13 order stay the same;
   verified by the existing matching tests and `forewarn match --osv` timed before and after (release build, the
   extracted npm archive, ~3,000 npm components) with identical output; makes true nothing new (VMT-1 to VMT-20 kept). (autonomous)
2. [ ] Count the clean components (MCH-3) against a hash set of the components matched or not evaluated
   (`ComponentRef` derives `Hash`); verified by the existing `cli-match` tests and the same timing; makes true nothing
   new (MCH-3 kept).

## Decisions
- Mode: autonomous
- Base commit: eccecb13c32049c9c13e70196ed4620a236778bf
- Measure on the real npm archive (220 MB) with an SBOM of ~3,000 npm components drawn from its package names, generated outside the repository.
- No committed load test: the existing tests cover the behaviour, the timings go in this issue.

## Deliverable 1
done: `match_components` looks the records of each component up in an index by ecosystem and name key (VMT-6);
`same_name` compares those keys.

| check | result |
|---|---|
| tests | `cardinal run project-check` passes |
| lint | clean |
| specs | unchanged, `check-specs` passes |
| docs | doc comment of `match_components`; nothing else describes the loop |
| measure | release build, 231,742 npm records, 3,000 npm components: 32.9 s before, 1.1 s after (1.0 s reading alone); JSON output byte-identical |

red: none (no behaviour change; the VMT tests stay green)

Code review: no findings

not verified: none

decisions needed: none
