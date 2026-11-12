---
priority: medium
depends_on: [check_sbom_completeness]
why: 'a false gap on a supplier the SBOM declares erodes trust in the check, but tools rarely omit the name'
---
# Count a supplier or author given only by URL or email

# Goal
The CycloneDX adapter keeps only the `name` of a supplier or manufacturer (an organizational entity) and of an author
(an organizational contact). A supplier given only by `url` or `contact`, or an author given only by `email`, is
dropped, so the completeness check reports the supplier missing although the SBOM declares it. BSI TR-03183-2 asks
for the creator's email or URL, so such entries are legitimate.

# Findings
* `crates/rollcall-cyclonedx/src/lib.rs` maps `supplier.name`, `manufacturer.name` and `authors[].name` only
  (SBR-5); an entry with no `name` gives an absent or empty domain field.
* Found by the `high` review of `check_sbom_completeness`.

# Approach
1. Amend SBR-5 so that a supplier, manufacturer or author with no name but a URL, a contact or an email is carried
   (e.g. its first URL or email as the value, or a richer domain type).
2. Amend SBC-4 if the wording of "has a supplier" changes, and add the scenarios.

# Specs
* `specs/sbom-reading.md`: SBR-5.
* `specs/sbom-completeness.md`: SBC-4.

# Milestone
Read and check an SBOM

# Resources
* `specs/sbom-reading.md`, `specs/sbom-completeness.md`.
* BSI TR-03183-2 (creator of the component: email or URL).
