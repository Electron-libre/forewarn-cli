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
