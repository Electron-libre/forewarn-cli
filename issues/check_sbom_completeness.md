---
priority: high
depends_on: [read_cyclonedx_sbom]
why: 'the completeness check is half of the milestone goal'
---
# Report the components missing the fields the CRA expects

# Goal
Raw scans often leave out the supplier, the license and the hashes of a component, fields the CRA expects in an SBOM.
A domain rule must list, for each component, which of these fields are missing, so that the vendor knows the gaps to
close.

# Approach
1. A pure domain function from the parsed components to a completeness report (per component: the missing fields),
   with no I/O.
2. Settle at step 1 what counts as present: e.g. a supplier given only as `author` or `publisher`, a license given as
   an expression, a hash with an unknown algorithm.
3. Consider the fields BSI TR-03183-2 requires as a reference for the list, kept as data so that it can grow.

# Specs
* `specs/sbom-completeness.md` (to write at step 1): the checked fields and what counts as present.

# Milestone
Read and check an SBOM

# Resources
* `CLAUDE.md`: what this is, hexagonal architecture.
* BSI TR-03183-2 (required SBOM fields).
* The fixtures added by `read_cyclonedx_sbom`.

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-12

## Understanding
A pure domain function from the components of an `Sbom` to a completeness report: per component, the missing fields
among supplier, license and hash (`specs/sbom-completeness.md`), the checked fields kept as data. Out of scope: the
CLI output (`cli_check_command`), the other BSI TR-03183-2 fields, the SBOM metadata.

## Plan
1. [x] Completeness check: `rollcall_domain::completeness` (checked fields as a constant list, presence rules, report
   with `is_complete`), spec `specs/sbom-completeness.md`; verified by tests in `crates/rollcall-domain/tests/` on
   built components and a happy-path test in `crates/rollcall-cyclonedx/tests/` on the `syft` fixture; makes true
   SBC-1 to SBC-7. (autonomous)

2. [x] High review fixes: Streebog-256/512 counted (CycloneDX 1.7 schema), `NOASSERTION` in any case, end-to-end
   checks of the cargo-cyclonedx and cdxgen fixtures, the tautological test removed, spec notes on `NONE` and hash
   values; verified by the domain and adapter tests; makes true SBC-4, SBC-5. (autonomous)

## Decisions
- Mode: autonomous
- Base commit: 80b29f00e3a690d33b0e9891ad1534c919805001
- Supplier present: `supplier`, `manufacturer`, an author or `publisher` (cargo-cyclonedx only writes `author`).
- License `NOASSERTION` counts as missing; `NONE` counts as present (an assertion).
- Hash: any algorithm of the CycloneDX enumeration counts, MD5 and SHA-1 included; not BSI's SHA-512 only.
- Hash with an algorithm outside the enumeration counts as missing.

## Deliverable 1 summary
done: `rollcall_domain::completeness` (`check`, `CompletenessReport`, `Field`, `CHECKED_FIELDS`), spec SBC accepted.

| check | result |
|---|---|
| tests | pass (10 domain, 1 adapter happy path) |
| lint | pass |
| specs | pass, SBC accepted, every requirement traced |
| docs | CLAUDE.md project status |
| code review | see below |

red: SBC-1, SBC-2, SBC-3, SBC-4, SBC-5, SBC-6, SBC-7, SBC-H2: unresolved import `rollcall_domain::completeness`
Code review: no findings

not verified: nothing.

decisions needed: none.

Follow-up: `Field` has no display name yet; the `rollcall check` command (`cli_check_command`) gives it its wording.

## Deliverable 2 summary
done: high review of the issue (9 findings) settled; SBC-4, SBC-5 amended, spec stays accepted.

| check | result |
|---|---|
| tests | pass (9 domain, 3 adapter on the three fixtures) |
| lint | pass |
| specs | pass |
| docs | spec only |
| code review | high: 9 findings; low: see below |

red: SBC-4, SBC-5: `noassertion` counted as a license (left [] right [License]); `Streebog-256` counted as missing (left [Hash] right [])

High review findings:
1. Streebog-256/512 missing from the 1.7 enumeration: fixed (checked on the official 1.7 schema).
2. Supplier or author with only a URL or an email is dropped by the adapter: outside SBC, filed as
   `issues/count_a_supplier_given_without_a_name.md`.
3. `NOASSERTION` compared with case: fixed.
4. Algorithm list duplicated as strings rather than a typed domain enum: not fixed, SBR-5 keeps the algorithm as
   written and the list is one constant.
5. Hash values not validated (hex, length): not fixed, stated as a non-goal of the spec.
6. Only the syft fixture checked end to end: fixed, cargo-cyclonedx and cdxgen added.
7. Tautological test on `CHECKED_FIELDS`: removed.
8. Name, version and purl cloned per incomplete component: not fixed, negligible and keeps the report owned.
9. `NONE` counts as a license: decided at validation (question 2), now stated in a scenario.

Code review: no findings

not verified: nothing.

decisions needed: none.

All deliverables done.
