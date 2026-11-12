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
