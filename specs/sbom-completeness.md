---
id: SBC
status: accepted
adrs: [0001]
---

# SBOM completeness

## Intent

Tell a vendor, for each component of an SBOM, which of the fields the CRA expects (supplier, license, hash) are
missing, so that they know the gaps to close before the SBOM is relied on. The list of checked fields follows BSI
TR-03183-2 and is kept as data so that it can grow.

## Requirements

### Behaviour

- **SBC-1** (deterministic) Checking the components of an SBOM must report each component that lacks at least one
  checked field, with the checked fields it lacks.
- **SBC-2** (deterministic) Checking must not report a component that has every checked field.
- **SBC-3** (deterministic) Checking must tell whether the SBOM is complete: no component reported, an SBOM with no
  component included.

### Contract

- **SBC-4** (deterministic) A checked field must count as present by the rule of this table, and as missing
  otherwise; a value that is empty or only whitespace counts as absent.

  | Field | Present when |
  |---|---|
  | supplier | the component has a supplier, a manufacturer, an author or a publisher |
  | license | the component has a license entry (an SPDX id, a name or an expression) other than `NOASSERTION` in any case |
  | hash | the component has a hash with a value and an algorithm the CycloneDX enumeration lists |

- **SBC-5** (deterministic) The hash algorithms that count must be those of the CycloneDX 1.7 enumeration, compared
  without regard to case: `MD5`, `SHA-1`, `SHA-256`, `SHA-384`, `SHA-512`, `SHA3-256`, `SHA3-384`, `SHA3-512`,
  `BLAKE2b-256`, `BLAKE2b-384`, `BLAKE2b-512`, `BLAKE3`, `Streebog-256`, `Streebog-512`.
- **SBC-6** (deterministic) A reported component must carry its name, its version when it has one and its package URL
  when it has one, and its missing fields in the order supplier, license, hash.
- **SBC-7** (deterministic) The reported components must keep the order of the SBOM, a component appearing twice
  being reported twice.

## Scenarios

- **SBC-H1** (happy; SBC-1, SBC-4, SBC-6) Given an SBOM a vendor generated with `syft`, whose components have no
  supplier and no license and only some a hash, when `forewarn` checks it, then each component is reported with
  supplier and license missing, and those with no hash also with hash missing.
- **SBC-H2** (happy; SBC-2, SBC-3) Given an SBOM whose every component has a supplier, a license and a SHA-256 hash,
  when `forewarn` checks it, then no component is reported and the SBOM is complete.
- (SBC-4) Given a component whose only creator is an `author`, when it is checked, then its supplier is present.
- (SBC-4) Given a component whose only license is the expression `MIT OR Apache-2.0`, when it is checked, then its
  license is present.
- (SBC-4) Given a component whose only license is `NOASSERTION` or `noassertion`, when it is checked, then its license
  is missing; with `NONE`, an assertion that it has no license, its license is present.
- (SBC-4) Given a component whose supplier is `"  "`, when it is checked, then its supplier is missing.
- (SBC-4, SBC-5) Given a component whose only hash has the algorithm `sha-256`, when it is checked, then its hash is
  present; with the algorithm `CRC32`, or with an empty value, its hash is missing.
- (SBC-3) Given an SBOM with no component, when it is checked, then nothing is reported and it is complete.

## Non-goals

- Fields BSI TR-03183-2 also requires but the issue leaves for later (file name, executable, archive and structured
  properties, dependencies, the creator's contact): the list of checked fields grows by amending this spec.
- Requiring a SHA-512 hash, as BSI TR-03183-2 does for the executable: any listed algorithm counts.
- Checking that a hash value is well formed for its algorithm (hexadecimal, length).
- Judging whether a license is valid SPDX, or whether a supplier name is real.
- Checking the SBOM's own metadata (`metadata.component`, `metadata.supplier`, timestamp).
- Rendering the report for a human or a CI job: the `forewarn check` command does (`specs/cli-check.md`).
