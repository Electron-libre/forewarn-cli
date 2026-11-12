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
