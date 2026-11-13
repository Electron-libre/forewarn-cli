---
id: EWD
status: accepted
adrs: [0011, 0012]
---

# Draft of the CRA early warning

## Intent

Give a vendor, for each match a list of exploited vulnerabilities names, a draft of the CRA article 14(2)(a) early
warning: the fields the tool knows exactly filled from the SBOM, the match and the moment of awareness, the fields only
the vendor knows marked to be completed, so that no field is guessed and none is forgotten.

## Requirements

### Behaviour

- **EWD-1** (deterministic) Drafting the early warnings of a flagged report (`specs/exploited-flagging.md`) must give
  one draft for each CVE id of the matches marked actively exploited, in the order its first match comes in the
  report.
- **EWD-2** (deterministic) Drafting must give no draft for a match that no list names.
- **EWD-3** (deterministic) A draft must name the product and its manufacturer as the SBOM describes them
  (`specs/sbom-reading.md`, SBR-9, SBR-10), and each affected component of its CVE, in the order of the report, with
  its version, its package URL and the id of its match, as the match names them.
- **EWD-4** (deterministic) A draft must carry the moment of awareness given to drafting and the deadlines
  `specs/reporting-deadlines.md` computes from it and from the moment a corrective or mitigating measure became
  available, when one is given.
- **EWD-5** (deterministic) A draft must carry the evidence of exploitation of its first match, as flagging gives it
  (EXF-1).
- **EWD-6** (deterministic) A draft must list as to complete each field the early warning requires (EWD-9) that the
  tool cannot fill from its inputs.

### Contract

- **EWD-7** (deterministic) The CVE id of a draft must be the CVE id of the first evidence of each of its matches, in
  upper case (EXF-9).
- **EWD-8** (deterministic) The EUVD id of a draft must be the first id that starts with `EUVD-`, ignoring ASCII case,
  among the id then the aliases of each of its matches in turn, and none when no id does.
- **EWD-9** (deterministic) The fields to complete must be taken from the fields the ENISA SRP glossary, version 1.6 of
  21 October 2026, marks required or mandatory in the early warning of an actively exploited vulnerability, in its
  order, as the table below says, and no other field.

| Glossary field | Filled from | To complete when |
|---|---|---|
| 2. Title | nothing | always |
| 3. Summary | nothing | always |
| 4. Manufacturer name | the manufacturer of the product | the SBOM names no product or no manufacturer |
| 5. Member States where product available | nothing | always |
| 6. Product Name | the name of the product | the SBOM names no product |
| 7. Product Version | the version of the product | the SBOM names no product or no version of it |
| v26. Date and time aware of the AEV | the moment of awareness | never |

- **EWD-10** (deterministic) A value of the product made only of white space (an empty name, version or
  manufacturer) must be read as absent, its field to complete.
- **EWD-11** (deterministic) Drafting the early warnings of a report with an actively exploited match must refuse,
  naming it, a moment whose deadline would fall after `9999-12-31T23:59:59Z` (RDL-10), and give no draft then.

## Scenarios

- **EWD-H1** (happy; EWD-1, EWD-3, EWD-4, EWD-5, EWD-6, EWD-7) Given an SBOM of `shop` `2.1.0` made by `Acme`, a
  component `log4j-core` `2.14.1` matched to `CVE-2021-44228`, which CISA KEV names since `2021-12-10`, and an
  awareness at `2026-11-13T09:30:00Z`, when the early warnings are drafted, then one draft names `shop` `2.1.0`,
  `Acme`, `log4j-core` `2.14.1`, `CVE-2021-44228`, the evidence of CISA KEV, the awareness, the early warning due by
  `2026-11-14T09:30:00Z` and the notification by `2026-11-16T09:30:00Z`, no final report deadline, and lists to
  complete the title, the summary and the Member States.
- **EWD-H2** (happy; EWD-1, EWD-2, EWD-3) Given a report of four matches, `log4j-core` to `CVE-2021-44228`, `openssl`
  to `CVE-2022-0778`, `log4j-api` to `CVE-2021-44228` and `zlib` to `CVE-2018-25032`, of which all but `zlib` are
  actively exploited, when the early warnings are drafted, then two drafts are given, the first for `CVE-2021-44228`
  naming `log4j-core` then `log4j-api`, the second for `CVE-2022-0778` naming `openssl`.
- (EWD-4) Given a measure available at `2026-11-15T17:00:00Z`, when the early warnings are drafted, then the final
  report of each draft is due by `2026-11-29T17:00:00Z`.
- (EWD-6, EWD-9) Given an SBOM naming no product, when the early warnings are drafted, then each draft names no product
  and lists to complete the title, the summary, the manufacturer name, the Member States, the product name and the
  product version, in that order.
- (EWD-6, EWD-9) Given a product with a name but no version nor manufacturer, when the early warnings are drafted, then
  each draft lists to complete the title, the summary, the manufacturer name, the Member States and the product
  version.
- (EWD-10) Given a product whose manufacturer is `"  "`, when the early warnings are drafted, then the manufacturer name
  is to complete.
- (EWD-3, EWD-7) Given a record `GHSA-jfh8-c2jp-5v3q` aliased to `cve-2021-44228` and matched to a component, which a
  list names, when it is drafted, then its CVE id is `CVE-2021-44228` and its component names the id of its match.
- (EWD-8) Given a match aliased to `euvd-2021-1234`, when it is drafted, then its EUVD id is `euvd-2021-1234`; given a
  match with no such alias, its EUVD id is none; given two matches of one CVE, the second alone aliased to
  `EUVD-2021-1234`, the EUVD id of their draft is `EUVD-2021-1234`.
- (EWD-5) Given a match that CISA KEV and EUVD both name, when it is drafted, then its draft carries both evidences, in
  the order of flagging.
- (EWD-1) Given a flagged report with no match, when the early warnings are drafted, then no draft is given.
- (EWD-11) Given an awareness at `9999-12-30T00:00:01Z` and an exploited match, when the early warnings are drafted,
  then drafting is refused naming that moment; with no exploited match, no draft is given and nothing is refused.

## Non-goals

- Writing a draft in a format (Markdown, JSON, the names and order of the SRP form): an adapter does
  (`write_the_early_warning_in_an_adapter`).
- Writing a title, a summary, an impact or any other prose: no field is composed as text from the inputs.
- The optional fields of the glossary the tool cannot fill (product type, class and category, end of support,
  mitigating measure expected, user actions, sensitivity, measures taken, general information, severity, impact,
  malicious actor): the adapter may list them, the domain does not.
- The fields of the 72-hour notification and of the final report, and the fields of a severe incident.
- Submitting the draft to the ENISA Single Reporting Platform: it has no API (SRP FAQ, 15 October 2026).
- Telling the Member States where a product is made available, or the CSIRT designated as coordinator.
- A draft for a component the vendor's verdict (VEX) marks not affected.
