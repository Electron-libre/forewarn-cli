---
id: EWD
status: accepted
adrs: [0011, 0012, 0013]
---

# Draft of the CRA early warning

## Intent

Give a vendor, for each match a list of exploited vulnerabilities names, a draft of the CRA article 14(2)(a) early
warning: the fields the tool knows exactly filled from the SBOM, the match and the moment of awareness, the fields only
the vendor knows marked to be completed, so that no field is guessed and none is forgotten, written as a Markdown
document a person copies into the ENISA Single Reporting Platform form.

## Requirements

### Behaviour

- **EWD-1** (deterministic) Drafting the early warnings of a flagged report (`specs/exploited-flagging.md`) must give
  one draft for each CVE id of the matches marked actively exploited, in the order its first match comes in the
  report.
- **EWD-2** (deterministic) Drafting must give no draft for a match that no list names.
- **EWD-3** (deterministic) A draft must name the product and its manufacturer as the SBOM describes them
  (`specs/sbom-reading.md`, SBR-9, SBR-10), and each affected component of its CVE, in the order of the report, with
  its version, its package URL and the id of its match, as the match names them, a component and id listed twice
  in the report named once.
- **EWD-4** (deterministic) A draft must carry the moment of awareness given to drafting and the deadlines
  `specs/reporting-deadlines.md` computes from it and from the moment a corrective or mitigating measure became
  available, when one is given.
- **EWD-5** (deterministic) A draft must carry the evidence of exploitation of its first match, as flagging gives it
  (EXF-1).
- **EWD-6** (deterministic) A draft must list as to complete each field the early warning requires (EWD-9) that the
  tool cannot fill from its inputs.
- **EWD-12** (deterministic) Writing a draft in Markdown must give, in this order, a title naming its CVE id, the list
  of the fields to complete (EWD-6), the moment of awareness with the deadlines of EWD-4, the evidence of EWD-5, then
  the fields of the early warning (EWD-14).
- **EWD-13** (deterministic) Writing a draft in Markdown must mark each field to complete with `**TO COMPLETE**` in
  its place among the fields.

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
| 4. Manufacturer name | the manufacturer of the product, to compare with the one the platform fills | never: the platform fills it, read-only |
| 5. Member States where product available | nothing | always |
| 6. Product Name | the name of the product | the SBOM names no product |
| 7. Product Version | the version of the product | the SBOM names no product or no version of it |
| v26. Date and time aware of the AEV | the moment of awareness | never |

- **EWD-10** (deterministic) A value of the product made only of white space (an empty name, version or
  manufacturer) must be read as absent, its field to complete.
- **EWD-11** (deterministic) Drafting the early warnings of a report with an actively exploited match must refuse,
  naming it, a moment whose deadline would fall after `9999-12-31T23:59:59Z` (RDL-10), and give no draft then.
- **EWD-14** (deterministic) The fields of a written draft must be the rows of the table below, in its order, each a
  list item `- **<field>**: <value>` with the number and the name of the glossary 1.6 (ADR 0012, ADR 0013).

| Field | Value written |
|---|---|
| 2. Title | `**TO COMPLETE**` |
| 3. Summary | `**TO COMPLETE**` |
| 4. Manufacturer name | the manufacturer, then `(filled by the platform from your registration: compare)`; without one, `not in the SBOM (filled by the platform from your registration)` |
| 5. Member States where product available | `**TO COMPLETE**` |
| 6. Product Name | the name of the product, else `**TO COMPLETE**` |
| 7. Product Version | the version of the product, else `**TO COMPLETE**` |
| 12. Component name | one nested item per affected component: its name, its version, its package URL and `match <id>`, those it lacks left out |
| v19. CVE ID | the CVE id |
| v20. EUVD ID | the EUVD id, else `none known` |
| v22. Date the corrective or mitigating measure became available | the moment of the measure, else `none given` |
| v26. Date and time aware of the AEV | the moment of awareness |

- **EWD-15** (deterministic) A written draft must give each moment and deadline in RFC 3339, in UTC, to the second
  (RDL-7), and a final report with no measure given as due 14 days after a corrective or mitigating measure is
  available, with no date (RDL-4).
- **EWD-16** (deterministic) A value of the SBOM or of a list written into a draft must have each ASCII punctuation
  character preceded by a backslash and each control character written as its escape (`\n`, `\u{1b}`), so that it
  reads as its text and forges no line, list item, emphasis, link or HTML.

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
- **EWD-H3** (happy; EWD-12, EWD-13, EWD-14, EWD-15) Given the draft of EWD-H1, when it is written in Markdown, then
  the document opens on a title naming `CVE-2021-44228`, lists `2. Title`, `3. Summary` and `5. Member States where
  product available` to complete, gives the awareness at `2026-11-13T09:30:00Z`, the early warning by
  `2026-11-14T09:30:00Z`, the notification by `2026-11-16T09:30:00Z` and the final report due 14 days after a measure
  is available, the evidence of CISA KEV added `2021-12-10`, then the fields from `2. Title` to `v26. Date and time
  aware of the AEV`, the three to complete marked `**TO COMPLETE**`, `6. Product Name` giving `shop` and `12.
  Component name` naming `log4j-core` `2.14.1`.
- (EWD-4) Given a measure available at `2026-11-15T17:00:00Z`, when the early warnings are drafted, then the final
  report of each draft is due by `2026-11-29T17:00:00Z`.
- (EWD-6, EWD-9) Given an SBOM naming no product, when the early warnings are drafted, then each draft names no product
  nor manufacturer and lists to complete the title, the summary, the Member States, the product name and the product
  version, in that order.
- (EWD-6, EWD-9) Given a product with a name but no version nor manufacturer, when the early warnings are drafted, then
  each draft names no manufacturer and lists to complete the title, the summary, the Member States and the product
  version.
- (EWD-10) Given a product whose name, version and manufacturer are made of white space, when the early warnings are
  drafted, then each draft names none of them and lists the product name and version to complete.
- (EWD-3, EWD-7) Given a record `GHSA-jfh8-c2jp-5v3q` aliased to `cve-2021-44228` and matched to a component, which a
  list names, when it is drafted, then its CVE id is `CVE-2021-44228` and its component names the id of its match.
- (EWD-8) Given a match aliased to `euvd-2021-1234`, when it is drafted, then its EUVD id is `euvd-2021-1234`; given a
  match with no such alias, its EUVD id is none; given two matches of one CVE, the second alone aliased to
  `EUVD-2021-1234`, the EUVD id of their draft is `EUVD-2021-1234`.
- (EWD-5) Given a match that CISA KEV and EUVD both name, when it is drafted, then its draft carries both evidences, in
  the order of flagging.
- (EWD-3) Given an SBOM listing `log4j-core` `2.14.1` twice, both matched to `CVE-2021-44228`, when the early
  warnings are drafted, then its draft names `log4j-core` once.
- (EWD-1) Given a flagged report with no match, when the early warnings are drafted, then no draft is given.
- (EWD-11) Given an awareness at `9999-12-30T00:00:01Z` and an exploited match, when the early warnings are drafted,
  then drafting is refused naming that moment; with no exploited match, no draft is given and nothing is refused.

- (EWD-13, EWD-14) Given a draft whose SBOM names no product, when it is written, then `6. Product Name` and `7.
  Product Version` read `**TO COMPLETE**`, the list of the fields to complete names them after the Member States, and
  `4. Manufacturer name` reads `not in the SBOM`.
- (EWD-14, EWD-15) Given a draft with an EUVD id and a measure available at `2026-11-15T17:00:00Z`, when it is
  written, then `v20. EUVD ID` gives the id, `v22.` gives `2026-11-15T17:00:00Z` and the final report is due by
  `2026-11-29T17:00:00Z`; with neither, they read `none known` and `none given`.
- (EWD-14) Given a component with no version nor package URL, when its draft is written, then its item gives its name
  and its match id only.
- (EWD-16) Given a component named `a|b*c_[x](y)<i>` and a product name holding a newline then `# Title`, when the draft
  is written, then the name reads `a\|b\*c\_\[x\]\(y\)\<i\>` and the product name stays on its line, the newline
  written `\\n` and the `#` escaped.

## Non-goals

- A JSON form of the written draft: no reader of it was found (ADR 0013); the JSON report of `forewarn match` is the
  machine-readable output.
- Writing the drafts to files or printing them from a command: `cli_draft_early_warnings` does.
- The time left before each deadline in the written draft: it depends on when it is read, which the report of
  `forewarn match` gives (MXL-22).
- Entering the draft into the platform form for the vendor, or the labels of the form's options (the notification
  type, the Member States).
- Writing a title, a summary, an impact or any other prose: no field is composed as text from the inputs.
- The optional fields of the glossary the tool cannot fill (product type, class and category, end of support,
  mitigating measure expected, user actions, sensitivity, measures taken, general information, severity, impact,
  malicious actor): the adapter may list them, the domain does not.
- The fields of the 72-hour notification and of the final report, and the fields of a severe incident.
- Submitting the draft to the ENISA Single Reporting Platform: it has no API (SRP FAQ, 15 October 2026).
- Telling the Member States where a product is made available, or the CSIRT designated as coordinator.
- A draft for a component the vendor's verdict (VEX) marks not affected.
