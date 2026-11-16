---
priority: high
why: 'without VEX a vendor cannot record that a match does not affect its product, so a beta tester has no way to silence a false positive and the CI keeps failing'
---
# Read the VEX verdicts of an SBOM and apply them to the matches

# Goal
`CLAUDE.md` names VEX for the exploitability verdicts, but `forewarn` reads none: `specs/sbom-reading.md` lists
"Services, dependencies and VEX statements" as non-goals for later milestones. A vendor that analysed a match
(e.g. the vulnerable function is never called) has no way to tell `forewarn`, so `match` keeps reporting it, keeps
exiting with 6 when it is exploited, and keeps drafting an early warning. `forewarn` should read CycloneDX VEX
verdicts and report a match the vendor marked not affected apart from the affected ones, out of the exit code and
the drafts.

# Findings
* `cyclonedx-bom` 0.9.0 (already a dependency of `forewarn-cyclonedx`) models `vulnerabilities[]` with
  `analysis.state`: `resolved`, `resolved_with_pedigree`, `exploitable`, `in_triage`, `false_positive`,
  `not_affected`, and `affects[].ref` naming the components by `bom-ref`.
* `specs/early-warning-draft.md` already lists as a non-goal "A draft for a component the vendor's verdict (VEX)
  marks not affected".
* The adapter (`crates/forewarn-cyclonedx/src/lib.rs`, `read_json`) reads no `vulnerabilities` today.
* Unknown: whether vendors ship VEX inside the SBOM or as a separate CycloneDX document (both are allowed); what
  CSAF VEX or OpenVEX support beta testers would ask for.

# Approach
1. Read the VEX of a CycloneDX document in the adapter (inside the SBOM, and/or a separate file given with an option
   such as `--vex <file>`) into domain types: per vulnerability id (CVE or other alias) and component, a verdict.
2. In the domain, apply the verdicts to the matches: `not_affected` and `false_positive` (and maybe `resolved`)
   take a match out of the affected ones; `exploitable` and `in_triage` keep it; a verdict for an id matches through
   the aliases of the match.
3. In the CLI: list the matches set aside by a verdict apart, with the verdict and its justification, in text and
   JSON; no exit code 6 and no draft for them.
Likely two deliverables (adapter and domain, then CLI); propose a split at step 1 if larger.

# Specs
* `specs/sbom-reading.md` (amends the non-goal on VEX), `specs/vulnerability-matching.md` or a new
  `specs/vex-verdicts.md`, `specs/cli-match.md`, `specs/cli-match-exploited.md`, `specs/early-warning-draft.md`.

# Milestone
Beta

# Resources
* `crates/forewarn-cyclonedx/src/lib.rs`, `crates/forewarn-domain/src/` (matching, exploited), `crates/forewarn/src/report.rs`.
* ADR 0002 (the `cyclonedx-bom` types never leave the adapter).
* CycloneDX 1.6 specification, `vulnerabilities[].analysis`.

# Hints
* A verdict must never hide a match silently: the report lists what was set aside and why.
* Keep the CRA deadlines unchanged for the matches a verdict leaves affected.
