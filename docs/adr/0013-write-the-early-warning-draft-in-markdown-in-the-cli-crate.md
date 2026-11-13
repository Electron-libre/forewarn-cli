# 0013. Write the early warning draft in Markdown, in a module of the CLI crate

- Status: accepted
- Date: 2026-11-13

## Context

The domain drafts the early warning of each actively exploited CVE (`specs/early-warning-draft.md`, ADR 0012) and
names its fields, not the form. Someone must write it in a format: the labels, numbers and order of the ENISA SRP
glossary, the fields to complete marked. The SRP has no API at launch (SRP FAQ, 15 October 2026): the reader is a
person filling the platform's web form.

ADR 0001 lets an adapter start as a module of a crate and become a crate when another consumer needs it alone. The
reports of `check` and `match` live in the module `report` of the CLI crate. A hosted Forewarn service may one day
render the same draft, but no such consumer exists yet.

## Decision

- **A module `early_warning` of the CLI crate** (`crates/forewarn/src/early_warning.rs`), beside `report`, writes a
  draft. It is the only code that knows the labels and order of the glossary: a change of the glossary or of the
  regulatory format touches it and the table of EWD-14, not the domain.
- **Markdown**, for a person: a title naming the CVE, the fields to complete listed first, the deadlines and the
  evidence, then each field of the glossary as a list item `- **<number>. <name>**: <value>`, a field to complete
  reading `**TO COMPLETE**`. Markdown reads as plain text in a terminal or an editor and renders in a CI artifact or a
  ticket.
- **Every value from the SBOM or a feed is escaped**: each ASCII punctuation character is preceded by a backslash
  (CommonMark allows it before any of them), each control character and each bidirectional or invisible formatting
  character is written as its escape, and a leading space as `&#32;`, so a component name cannot open a list item, a
  heading, a code block, a link or HTML, nor reorder or hide the text a person copies into the form.
- **No JSON form**: no reader of it was found; the JSON report of `forewarn match` already serves a machine.

## Consequences

- The module moves to a crate of its own (e.g. `forewarn-report`) when the hosted service needs it, with `report`;
  until then the CLI crate is the only consumer.
- A new glossary version updates the table of EWD-14 and the labels of the module together.
- Escaping every ASCII punctuation character makes the Markdown source noisier (`pkg:maven/org\.apache...`), its
  rendering exact.
