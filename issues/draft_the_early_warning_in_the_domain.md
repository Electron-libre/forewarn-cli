---
priority: high
depends_on: [read_the_product_of_the_sbom]
why: 'the content of the draft early warning, the core of the milestone; the adapter and the CLI only write it'
---
# Draft the CRA early warning of an actively exploited match in the domain

# Goal
For each match marked actively exploited, `forewarn match` prints the evidence and the CRA article 14(2) deadlines, but
the vendor still writes the early warning from scratch. The domain should build a draft early warning from a flagged
match, the product of the SBOM and the moment of awareness: the fields the tool knows filled, the fields only the
vendor knows marked to be completed, with no I/O and no knowledge of any output format.

# Findings
* The ENISA Single Reporting Platform (SRP), the channel of article 14 reports, opened on 11 September 2026. Secondary
  sources (searched 2026-11-13) say it has no API at launch: reports are entered in a web form, so the draft is
  copied field by field by a person.
* The same sources say an ENISA glossary of the SRP lists the fields of each notification (counts of 39 to 43 fields
  are reported), but disagree on which fields the early warning makes mandatory (moment of awareness in UTC, type and
  level of notification, manufacturer, product, title, Member States where the product is made available "where
  applicable"). No primary ENISA document was read yet.
* The domain already has the flagged match with its evidence (`exploited.rs`) and the deadlines (`deadlines.rs`).

# Approach
1. Measure first: read the ENISA SRP FAQ and glossary themselves; note their version, the fields of an early warning
   for an actively exploited vulnerability, which are mandatory, and their allowed values. Record the source and its
   version in an ADR, so that a later glossary change says what to update.
2. A domain type `EarlyWarning` aligned on those fields: the product and manufacturer (from
   `read_the_product_of_the_sbom`), the affected component, the CVE and the vulnerability id, the evidence of
   exploitation, the moment of awareness and the deadlines; each field the tool cannot know (Member States,
   description of the impact, contact) present as "to complete", never guessed.
3. Scenarios: one draft per exploited match, none for a match no list names; a missing product or manufacturer kept
   as "to complete"; the deadlines equal to those of `specs/reporting-deadlines.md`.

# Specs
* `specs/early-warning-draft.md` (new, written at step 1): the content of a draft and where each field comes from.

# Milestone
Draft the CRA early warning

# Resources
* Regulation (EU) 2024/2847 (Cyber Resilience Act), article 14(2)(a) and 14(1).
* ENISA Single Reporting Platform: its FAQ and its glossary (to locate at step 1).
* `crates/forewarn-domain/src/exploited.rs`, `crates/forewarn-domain/src/deadlines.rs`.
* `specs/exploited-flagging.md`, `specs/reporting-deadlines.md`, ADR 0011.
* `CLAUDE.md`: "Hexagonal architecture", "Deterministic", "Testing priority".

# Hints
* Deterministic, no LLM: a field the tool cannot derive exactly stays to be completed, it is not written as prose.
* The format of the draft belongs to an adapter (`write_the_early_warning_in_an_adapter`): no field name of the SRP
  form in the domain beyond what the type needs.

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-13

## Understanding
A domain module `early_warning` turns a flagged report, the SBOM's product, the moment of awareness and an optional
measure moment into one `EarlyWarning` per CVE of the exploited matches, listing their components, with the required fields of the ENISA SRP glossary 1.6 it
cannot fill listed as to complete. Out of scope: any format, the CLI. No contact field (the glossary has none).

## Plan
1. [x] Draft the early warning: module `forewarn-domain::early_warning` (`EarlyWarning`, `ToComplete`,
   `draft_early_warnings`), spec `early-warning-draft` and ADR 0012; verified by
   `crates/forewarn-domain/tests/early_warning.rs` (~600 lines); makes true EWD-1 to EWD-11. (autonomous)

## Decisions
- Mode: autonomous
- Base commit: 8e41c409dbc758dfed70763a8fc82e55f0d74fe9
- One draft per CVE and product, listing the affected components, not one per match (answer 1 a).
- Title and summary always to complete, never composed (answer 2 a).
- Manufacturer taken from the SBOM though the SRP fills its own, for the vendor to compare (answer 3 a).
- Source measured at step 1: ENISA CRA SRP Glossary v1.6 (21 October 2026) and SRP FAQ (15 October 2026, no API at
  the initial release), recorded in ADR 0012.

## Deliverable 1
- done: module `forewarn_domain::early_warning` (`EarlyWarning`, `AffectedComponent`, `ToComplete`,
  `draft_early_warnings`), one draft per exploited CVE; spec `early-warning-draft` accepted; ADR 0012; `CLAUDE.md`
  status line.
- checks: project-check (fmt, clippy, tests, specs) pass; docs updated.
- red: EWD-1, EWD-2, EWD-3, EWD-4, EWD-5, EWD-6, EWD-7, EWD-8, EWD-9, EWD-10, EWD-11, EWD-H1, EWD-H2: unresolved
  import `forewarn_domain::early_warning`.
- Code review: 1 findings: deadlines refused with no exploited match (fixed: computed only when a draft is given,
  EWD-11 narrowed, test added).
- not verified: none.
- decisions needed: none.
