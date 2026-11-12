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

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-12

## Understanding
The adapter falls back, when a supplier, manufacturer or author has no usable name, to its first URL or contact
email (author: its email), so the completeness check sees the creator BSI TR-03183-2 accepts. The domain keeps a
plain string: SBC-4 is unchanged (a supplier given by URL or email is "a supplier"). Phone numbers do not count.

## Plan
1. [x] Identity fallback in the CycloneDX adapter: name, then URL, then contact email (author: name, then email),
   blank values skipped; verified by tests in `crates/rollcall-cyclonedx/tests/reading.rs` and one through
   `rollcall check`; makes true SBR-5 (amended). (autonomous)

## Decisions
- Mode: autonomous
- Base commit: ca4e148f4d6db7f30bd790f1e578eef323168e1c
- 1 a: the name of a contact does not identify a supplier or a manufacturer; only its URLs and contact emails do.
- 2 a: a phone number does not count.

## Deliverable 1 summary
done: the adapter carries a supplier or manufacturer by its name, else its first URL, else a contact email, and an
author by its name, else its email, blank values skipped (SBR-5 amended, spec back to `accepted`).

| check | result |
|---|---|
| tests | pass |
| lint | pass |
| specs | pass |
| docs | doc comments of `Component`; README n/a (unchanged wording) |
| code review | 1 finding, fixed |

red: SBR-5, SBC-4: `left: None, right: Some("https://example.com")`; `rollcall check` exited 1 instead of 0.

Code review: 1 findings
- The identity paragraph of SBR-5 split the field table in two: moved below the table.

not verified: none
decisions needed: none

## Whole-issue review (high)
Code review: 6 findings
- Fallback order URL before email: fixed in deliverable 2, email first as BSI TR-03183-2 asks (overrides the order
  of the plan).
- Blank legacy `author` kept: not fixed, pre-existing behaviour; the completeness check already counts it absent.
- Plain string for a name, URL or email: not fixed, the validated plan keeps a plain string (decision of step 2).
- Blank rule in adapter and domain: not fixed, the adapter needs it to choose the fallback.
- Allocation of skipped candidates: not fixed, negligible.
- End-to-end test asserts the exit code only: not fixed, the mapping is proved by the reading tests.

2. [x] Review fixes: email before URL in the organization identity; verified by the reading tests; makes true SBR-5.
   (autonomous)

## Deliverable 2 summary
done: the identity of an organization takes its contact emails before its URLs (spec, code, test, doc comment).

| check | result |
|---|---|
| tests | pass |
| lint | pass |
| specs | pass |
| docs | doc comments of `Component` |
| code review | no findings |

red: none

Code review: no findings

not verified: none
decisions needed: none
