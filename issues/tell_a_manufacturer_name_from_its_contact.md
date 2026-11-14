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

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-14

## Understanding
The product's manufacturer and supplier become the organization's `name` only (new SBR-12, SBR-10 withdrawn); an
organization given only by a contact email or a URL gives none, so the draft reads `not in the SBOM`. Components keep
the fallback of SBR-5: the completeness check is unchanged. No contact is drafted (the glossary has no field, ADR 0012).
Measure: none of the `cargo-cyclonedx`, `syft`, `cdxgen` fixtures gives a product manufacturer or supplier at all.

## Plan
1. [x] Name only: the adapter takes the product's manufacturer and supplier from the first non-blank `name`, the doc
   comments of `Product` say so, the SBR-10 tests retargeted; verified by `crates/forewarn-cyclonedx/tests/reading.rs`
   and a `match --drafts` test in `crates/forewarn/tests/drafts.rs` (manufacturer by email only → `not in the SBOM`);
   makes true SBR-12, EWD-3 (~80 lines). (autonomous)

## Decisions
- Mode: autonomous
- Base commit: 9991ae08acd54f772cf78f10e664bf1dc70cf0de
- Question 1: a, name only for the manufacturer and the supplier of the product, the contact dropped.

## Summary of deliverable 1
- done: the product's manufacturer and supplier are read from the first non-blank `name` only (SBR-12, SBR-10
  withdrawn); a draft whose manufacturer has only a contact reads `not in the SBOM`; `sbom-reading` back to `accepted`.

| check | result |
|---|---|
| tests | pass (`cardinal run project-check`) |
| lint | pass |
| specs | pass (`check-specs`) |
| docs | doc comments of `Product` and `product`; README and CLAUDE.md n/a (they do not describe the field) |
| code review | `low`, no findings |

- red: SBR-12, EWD-3, EWD-14: `left: Some("security@acme.example") right: None`; the draft read
  `- **4. Manufacturer name**: security\@acme\.example (filled by the platform from your registration: compare)`.
- Code review: no findings
- not verified: none
- decisions needed: none
