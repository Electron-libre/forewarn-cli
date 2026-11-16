# 0014. Apply the VEX verdicts in the domain, after the flagging, components known by their `bom-ref`

- Status: proposed
- Date: 2026-11-16

## Context

A vendor records in CycloneDX VEX that a vulnerability does not affect a component of their product
(`vulnerabilities[].analysis`), either inside the SBOM or in a document of its own. A verdict names the vulnerability
by its id and the references that alias it, and the component by its `bom-ref` (`affects[].ref`), a BOM-Link when the
VEX is a document apart. `forewarn` matches components against feeds, then flags the matches a list of exploited
vulnerabilities names, then computes deadlines and drafts early warnings from the flagged report. ADR 0002 keeps the
`cyclonedx-bom` types inside the adapter; the domain knows a component by its name, version and package URL only.

## Decision

- **The adapter reads the verdicts into domain types** (`forewarn_domain::vex::Verdict`: ids, targets, state,
  justification, detail), from the SBOM (`read_json` returns them beside the components) and from a VEX document
  (`read_vex_json`). The `cyclonedx-bom` types stay in the adapter.
- **A component carries its `bom-ref`** into the domain (`Component`, `ComponentRef`), the only key a verdict names a
  component by. A BOM-Link target is reduced to its `bom-ref` by the adapter.
- **The domain applies the verdicts to the flagged report**, after `flag_exploited`: the matches set aside keep their
  evidence, so the report says when a vendor set aside an actively exploited vulnerability, and the deadlines and the
  drafts, built from the matches left, need no change.
- **A verdict keeps a match unless every verdict naming it sets it aside**: a conflict never hides a match.

## Consequences

- A rule on verdicts (a new state, CSAF VEX or OpenVEX read by another adapter) touches the domain module `vex` and an
  adapter, never the matching, the flagging, the deadlines or the drafts.
- A verdict can name a component only when the SBOM gives it a `bom-ref`; the tools named in SBR-4 all write one.
- The flagged report grows a list of matches set aside, which the report formats print.
