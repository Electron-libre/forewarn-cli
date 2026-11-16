---
priority: low
why: 'only the clean count of the report is off, never a match nor the exit code; it needs two components of the same name, version and package URL'
---
# Count each component of the SBOM apart in the clean count

# Goal
`forewarn match` prints how many components are clean (MCH-3, `cleanCount`). It tells them by name, version and
package URL (`ComponentRef`), so two components of the SBOM with the same three, one reported and one clean, both
drop out of the count: the report undercounts the clean components. First-party flagging (SBR-14) makes the case
likelier: a module nested in the product, first-party, and the same module listed at the top level without a
`bom-ref`, matched and clean. Count each component of the SBOM by its place in it.

# Findings
* Raised by the `high` review of `keep_first_party_components_out_of_the_osv_match` (2026-11-16).
* `clean_count` in `crates/forewarn/src/report.rs` builds a set of the `ComponentRef` of the matches and the
  components not evaluated, then counts the components of the SBOM whose `ComponentRef` is not in it.

# Approach
1. Write the failing case: two components of the same name, version and package URL, one not evaluated
   (first-party), one clean; the report must say 1 clean.
2. Candidates: the domain gives each match and each component not evaluated the index of its component in the SBOM;
   or the matching returns the clean components itself.

# Specs
* `specs/cli-match.md` (MCH-3), maybe `specs/vulnerability-matching.md` (VMT-13, which already orders by the
  component's place in the SBOM).

# Resources
* `crates/forewarn/src/report.rs` (`clean_count`), `crates/forewarn-domain/src/matching.rs` (`ComponentRef`).

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-16

## Understanding
`cleanCount` must count each component of the SBOM by its place, not by name, version and package URL. Out of scope:
any change to the matches, the components not evaluated, or the exit code. Means: the domain's `MatchReport` counts
the clean components while matching (a component that gave no match and nothing not evaluated), `FlaggedReport`
carries the count, and `report::clean_count` and its `HashSet` of `ComponentRef` go.

## Plan
1. [x] Count the clean components in the matching: `MatchReport` and `FlaggedReport` give the count, the reports
   print it; verified by an end-to-end test through `forewarn match --osv` on an SBOM nesting `mod-a` 1.0 in the
   product and listing it again at the top level (1 clean), plus a domain unit test; makes true MCH-3 (amended). (autonomous)

## Decisions
- Mode: autonomous
- Base commit: 4e50832e3ec70b2f7c0f03681ff07db53d0bc196

## Summary of deliverable 1
- done: `MatchReport::clean_count` counts, while matching, each component that gave no match nor pair or component
  not evaluated; `FlaggedReport` carries it; `report::clean_count` and its set of `ComponentRef` are gone.
- red: MCH-3: `left: Number(0) right: Number(1)` (`cleanCount` of the SBOM listing `mod-a` 1.0 nested and at the top
  level).
- Docs: n/a, README.md says "how many are clean", still true; spec MCH-3 amended, back to `accepted`.
- Code review: no findings (its doubt on unused imports is settled: the project check passes, `ComponentRef` and
  `Sbom` are still used in `report.rs`).
- Not split: `crates/forewarn-domain/tests/matching.rs` was already over the file size limit (1,184 lines) before this
  deliverable; splitting it is a change of its own.
