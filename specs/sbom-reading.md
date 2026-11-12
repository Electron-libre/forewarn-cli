---
id: SBR
status: accepted
adrs: [0001, 0002]
---

# SBOM reading

## Intent

Read a CycloneDX JSON SBOM, produced by an existing tool, into the components of the domain, and tell whether its
spec version meets the BSI TR-03183-2 minimum (1.6), so that the completeness check and the matching work on them.

## Requirements

### Behaviour

- **SBR-1** (deterministic) Reading a CycloneDX JSON SBOM of spec version 1.6 or 1.7 must return its components and
  its spec version, with no outdated flag.
- **SBR-2** (deterministic) Reading a CycloneDX JSON SBOM of spec version 1.3, 1.4 or 1.5 must return its components
  with its spec version flagged as below the BSI TR-03183-2 minimum.
- **SBR-3** (deterministic) Reading an input that is not a readable CycloneDX JSON SBOM must fail with an error that
  names the cause, from the table of SBR-7.
- **SBR-4** (deterministic) The SBOMs produced by `cargo-cyclonedx`, `syft` and `cdxgen` must be read without error.

### Contract

- **SBR-5** (deterministic) Each component read must carry the fields of this table, taken from the CycloneDX
  component as stated, an absent CycloneDX field giving an absent or empty domain field.

  | Domain field | CycloneDX source |
  |---|---|
  | name | `name` |
  | version | `version` |
  | package URL | `purl`, as written |
  | supplier | `supplier.name` |
  | manufacturer | `manufacturer.name` (1.6) |
  | authors | `author` when present, then the `name` of each entry of `authors` (1.6) that has one |
  | publisher | `publisher` |
  | licenses | each entry of `licenses`: the SPDX id or the name of a `license`, or the text of an `expression` |
  | hashes | each entry of `hashes`: the algorithm as written and the value |

- **SBR-6** (deterministic) The components nested in a component (`components[].components`, at any depth) must be
  returned in the same flat list as the top-level ones, in document order, each parent before its children.
- **SBR-7** (deterministic) A refused input must fail with the error of this table, the first cause that applies in
  table order, its message quoting the offending value when there is one.

  | Cause | Error |
  |---|---|
  | the input cannot be read (an I/O error) | cannot read the input, with the system's reason |
  | the input is not JSON | not JSON |
  | `bomFormat` is absent or is not `CycloneDX` | not a CycloneDX SBOM |
  | `specVersion` is absent or is not a string | missing spec version |
  | `specVersion` is not 1.3, 1.4, 1.5, 1.6 or 1.7 | unsupported spec version, quoting it |
  | the document does not match its spec version | invalid SBOM, with the parser's reason |

- **SBR-8** (deterministic) Reading must not refuse nor drop a component whose type or hash algorithm is a value the
  CycloneDX enumerations do not list.

## Scenarios

- **SBR-H1** (happy; SBR-1, SBR-4, SBR-5) Given an SBOM a vendor generated with `syft` in CycloneDX 1.6, when
  `rollcall` reads it, then it gets every component with the name, version, package URL and hashes `syft` wrote, and
  spec version 1.6 with no flag.
- **SBR-H2** (happy; SBR-2) Given an SBOM in CycloneDX 1.5, when `rollcall` reads it, then it gets its components and
  the warning that 1.5 is below the BSI TR-03183-2 minimum.
- (SBR-7) Given a CycloneDX 1.2 JSON file, when it is read, then it fails with "unsupported spec version" quoting `1.2`.
- (SBR-7) Given a JSON file with `bomFormat` `CycloneDX` and no `specVersion`, when it is read, then it fails with
  "missing spec version".
- (SBR-7) Given an SPDX JSON document, when it is read, then it fails with "not a CycloneDX SBOM".
- (SBR-7) Given a 1.6 document whose `components` is a string, when it is read, then it fails with "invalid SBOM".
- (SBR-5) Given a component with no supplier, no licenses and no hashes, when it is read, then it is returned with
  those fields absent or empty, not refused.
- (SBR-1) Given a valid 1.6 SBOM preceded by a UTF-8 byte-order mark, when it is read, then it is read as without it.
- (SBR-1) Given a valid 1.6 SBOM with no `components`, when it is read, then it returns an empty list.

## Non-goals

- XML or Protobuf input.
- SPDX input, or converting another format to CycloneDX.
- Detecting dependencies: the input is always an SBOM produced by another tool.
- Validating the SBOM against the CycloneDX JSON schema beyond what parsing needs.
- The component the SBOM describes (`metadata.component`), services, dependencies and VEX statements: later
  milestones read them.
- Deciding whether a field counts as present for the CRA: the completeness check (`specs/sbom-completeness.md`) does.
- Reading the file from disk or standard input: the command line does.
