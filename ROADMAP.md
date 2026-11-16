# Roadmap

The planned work of the project, grouped into milestones, in the order they are meant to land: the user orders them.
A milestone becomes issues once it is shaped (`skill:create-issue`); the `priority` and `depends_on` of each issue file order them within a milestone (`cardinal run next-issue`).
States: `idea`, `shaped`, `in issues`, `done` (set by `cardinal run close-issue` when the last issue of an `in issues` one closes); `cardinal run release` adds `- Released: v<version>` to a `done` one and moves it to `ROADMAP-done.md` (`roadmap_archive`). A milestone carries no date unless the project gives it one. `cardinal run roadmap` prints the state of every milestone.
A line `- On hold: <reason>` defers a milestone: `cardinal run next-issue` offers none of its issues until it is removed.

## Draft the CRA early warning

- Goal: for each affected component, `forewarn` writes a draft CRA early warning with its deadlines, in a format an
  adapter owns so that a change of the regulatory format only touches it.
- Why: a vendor should not write the report from scratch under pressure.
- State: done
- Issues:
  - [read_the_product_of_the_sbom](issues/done/read_the_product_of_the_sbom.md)
  - [draft_the_early_warning_in_the_domain](issues/done/draft_the_early_warning_in_the_domain.md)
  - [write_the_early_warning_in_an_adapter](issues/done/write_the_early_warning_in_an_adapter.md)
  - [cli_draft_early_warnings](issues/done/cli_draft_early_warnings.md)
  - [keep_the_euvd_id_of_an_exploited_entry](issues/done/keep_the_euvd_id_of_an_exploited_entry.md)
  - [tell_a_manufacturer_name_from_its_contact](issues/done/tell_a_manufacturer_name_from_its_contact.md)

## Proof-of-concept demo

- Goal: a 20-second demo shows the whole run (SBOM, matching, exploited flag, draft early warning) on a real project.
- Why: completes the proof of concept and shows what the tool does without reading the docs.
- State: in issues
- Issues:
  - [choose_a_distinct_product_name](issues/done/choose_a_distinct_product_name.md)
  - [tell_each_record_status_apart_in_the_match_report](issues/tell_each_record_status_apart_in_the_match_report.md)
  - [tell_file_components_apart_in_the_completeness_check](issues/tell_file_components_apart_in_the_completeness_check.md)

## Upload from CI

- Goal: `forewarn` uploads the SBOM and AI-BOM with product, version and date to a Forewarn service, whose URL is set
  by `--endpoint` or an environment variable.
- Why: keeps a vendor's inventory up to date without manual work; only inventories leave the CI, never source code.
- State: idea

## CI integration templates

- Goal: ready-to-use examples run `forewarn` at each release in GitHub Actions and GitLab CI.
- Why: lowers the cost of adoption to a copy-paste.
- State: idea
