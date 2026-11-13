---
priority: medium
depends_on: [draft_the_early_warning_in_the_domain]
why: 'a draft early warning shows an email or a URL as the manufacturer name when the SBOM gives no name'
---
# Tell the name of a manufacturer from its contact in the product of an SBOM

# Goal
The domain's `Product::manufacturer` (and `supplier`) holds the organisation's name, else a contact email, else a URL
(SBR-10). The draft early warning (`specs/early-warning-draft.md`, EWD-3) shows it as the manufacturer name, so an SBOM
whose manufacturer has only `contact[].email` yields a manufacturer name `security@acme.example`. The draft should
name a manufacturer only by its name, and show a contact apart, or nothing.

# Findings
* `crates/forewarn-cyclonedx/src/lib.rs` (`organization`): `name`, then the emails of `contact`, then `url`, the
  first filled.
* The completeness check (`specs/sbom-completeness.md`) relies on the same fallback to count a supplier given without
  a name (`issues/done/count_a_supplier_given_without_a_name.md`).
* Found by the `high` review of `draft_the_early_warning_in_the_domain` (2026-11-13).

# Approach
1. Measure: which real SBOMs (fixtures of `cargo-cyclonedx`, `syft`, `cdxgen`) give a manufacturer without a name.
2. Candidates: an organisation type in the domain (name, emails, urls) instead of one string; or the draft takes the
   manufacturer only when the adapter read it from a name.
3. Keep the completeness check as it is: a supplier given by its contact still counts.

# Specs
* `specs/sbom-reading.md` (SBR-10), `specs/early-warning-draft.md` (EWD-3).

# Milestone
Draft the CRA early warning

# Resources
* `crates/forewarn-domain/src/sbom.rs`, `crates/forewarn-cyclonedx/src/lib.rs`,
  `crates/forewarn-domain/src/early_warning.rs`.
* ADR 0002 (the `cyclonedx-bom` types never leave the adapter), ADR 0012.
