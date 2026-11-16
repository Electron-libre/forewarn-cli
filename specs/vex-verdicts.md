---
id: VEX
status: accepted
adrs: [0002, 0014]
---

# VEX verdicts

## Intent

Read the verdicts a vendor recorded in CycloneDX VEX, inside the SBOM or in a document of its own, and set aside the
matches a verdict says do not affect the product, each with the verdict that set it aside, so that a vendor who
analysed a false positive is not asked to report it while the report still shows what was set aside and why.

## Requirements

### Behaviour

- **VEX-1** (deterministic) Reading a CycloneDX JSON SBOM must return, beside its components (SBR-1), the verdicts of
  its `vulnerabilities`: for each vulnerability with an `analysis.state`, its ids, the components it affects, its
  state, its justification and its detail.
- **VEX-2** (deterministic) Reading a CycloneDX JSON VEX document, a CycloneDX document with `vulnerabilities` and with
  or without `components`, must return its verdicts as VEX-1 says.
- **VEX-3** (deterministic) Applying verdicts to a flagged report (`specs/exploited-flagging.md`) must move each match
  a verdict that sets aside (VEX-8) names (VEX-6, VEX-7) out of the matches into the matches set aside, each with
  that verdict and the evidence of the lists naming it.
- **VEX-4** (deterministic) Applying verdicts must leave among the matches, unchanged, each match no verdict names
  and each match a verdict that keeps it (VEX-8) names.

### Contract

- **VEX-5** (deterministic) A verdict must carry the fields of this table, taken from a vulnerability of the CycloneDX
  document as stated, a blank value (empty or only whitespace) skipped.

  | Verdict field | CycloneDX source |
  |---|---|
  | ids | `id`, then the `id` of each entry of `references`, in document order |
  | targets | the `ref` of each entry of `affects`, in document order |
  | state | `analysis.state`, as written |
  | justification | `analysis.justification`, as written (`code_not_reachable`), or none |
  | detail | `analysis.detail`, as written, or none |

- **VEX-6** (deterministic) A verdict must name a match when one of its ids equals the id or an alias of the match
  (VMT-16, VMT-17), a CVE id compared in upper case.
- **VEX-7** (deterministic) A verdict must name the component of a match when one of its targets equals the
  `bom-ref` of the component (SBR-16), a BOM-Link (`urn:cdx:<serial number>/<version>#<bom-ref>`) being compared by
  its percent-decoded `bom-ref`; a target that is the `bom-ref` of no component of the SBOM names each component
  whose package URL equals it as written.
- **VEX-8** (deterministic) A verdict must set a match aside or keep it by its state, as this table says, a state the
  table does not list keeping it.

  | State | Effect |
  |---|---|
  | `not_affected` | sets aside |
  | `false_positive` | sets aside |
  | `resolved` | sets aside |
  | `resolved_with_pedigree` | as `resolved` |
  | `exploitable` | keeps |
  | `in_triage` | keeps |

- **VEX-9** (deterministic) A match several verdicts name must be set aside only when each of them sets it aside, with
  the first of them in the order of the verdicts given (those of the SBOM, then those of each VEX document in turn).
- **VEX-10** (deterministic) The matches set aside must keep the order of the matches (VMT-13).
- **VEX-13** (deterministic) Applying no verdict must return the flagged report unchanged.
- **VEX-11** (deterministic) A vulnerability without `analysis`, or whose `analysis` has no `state`, must give no
  verdict, and a document with no `vulnerabilities` (any CycloneDX 1.3 document) none at all.
- **VEX-12** (deterministic) A VEX document that is not a readable CycloneDX JSON document must be refused with the
  error of SBR-7 that applies, a document of spec version 1.3 being read with no verdict.

## Scenarios

- **VEX-H1** (happy; VEX-1, VEX-3, VEX-5, VEX-6, VEX-7, VEX-8) Given an SBOM listing `log4j-core` 2.14.1 under the
  `bom-ref` `log4j`, and a vulnerability `CVE-2021-44228` affecting `log4j` with the state `not_affected` and the
  justification `code_not_reachable`, when `GHSA-jfh8-c2jp-5v3q` (alias `CVE-2021-44228`) matches `log4j-core` and the
  CISA KEV catalog names the CVE, then the match is set aside with that verdict and its KEV evidence, and no match
  is left.
- **VEX-H2** (happy; VEX-2, VEX-3, VEX-4) Given an SBOM without `vulnerabilities` and a VEX document saying
  `not_affected` for one of two matches and `in_triage` for the other, when its verdicts are applied, then the first
  match is set aside and the second stays among the matches.
- (VEX-6) Given a verdict whose id is `cve-2021-44228`, when it is applied to a match whose alias is `CVE-2021-44228`,
  then it names the match; a verdict whose id is `GHSA-JFH8-C2JP-5V3Q` does not name the match of
  `GHSA-jfh8-c2jp-5v3q`.
- (VEX-6) Given a verdict whose `id` is `INTERNAL-1` and whose `references` hold `CVE-2021-44228`, when it is applied to
  the match of `CVE-2021-44228`, then it names it.
- (VEX-7) Given a verdict naming the right vulnerability but the `bom-ref` of another component, when it is applied,
  then the match stays.
- (VEX-7) Given a VEX document whose target is `urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/1#pkg%3Amaven%2Flog4j`, when
  it is applied to an SBOM whose component has the `bom-ref` `pkg:maven/log4j`, then it names it, whatever the serial
  number of the SBOM.
- (VEX-7) Given an SBOM written by `syft`, whose `bom-ref`s are `pkg:cargo/time@0.1.43?package-id=…`, and a verdict
  whose target is `pkg:cargo/time@0.1.43`, when it is applied, then it names the component `time`; given a component
  whose `bom-ref` is that target, it names that component alone.
- (VEX-9) Given one verdict `not_affected` and one `exploitable` for the same match, in either order, when they are
  applied, then the match stays.
- (VEX-8) Given a verdict whose state is `not_affected` for a match no list names, when it is applied, then it is set
  aside with no evidence.
- (VEX-11) Given a vulnerability with `ratings` and no `analysis`, as a scanner writes into an SBOM, when it is read,
  then it gives no verdict.
- (VEX-12) Given a VEX document whose `bomFormat` is absent, when it is read, then it is refused with "not a CycloneDX
  SBOM".

## Non-goals

- CSAF VEX and OpenVEX: only CycloneDX VEX is read, until a beta tester asks for another.
- Checking the serial number and the version of a BOM-Link against the SBOM: an SBOM regenerated at each build gets a
  new serial number, and the vendor's VEX would stop applying.
- The `affects[].versions` of a target, its `analysis.response`, `firstIssued` and `lastUpdated`: the verdict applies
  to the component the target names, whatever its version.
- Setting aside a component or a pair not evaluated (VMT-10): a verdict only applies to a match.
- Using the vulnerabilities of an SBOM or a VEX document as a source of matches: the feeds are (`specs/cli-match.md`).
- Deciding whether a justification is enough for the CRA: the verdict is the vendor's, reported as written.
