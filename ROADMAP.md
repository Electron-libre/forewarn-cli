# Roadmap

The planned work of the project, grouped into milestones, in the order they are meant to land: the user orders them.
A milestone becomes issues once it is shaped (`skill:create-issue`); the `priority` and `depends_on` of each issue file order them within a milestone (`cardinal run next-issue`).
States: `idea`, `shaped`, `in issues`, `done` (set by `cardinal run close-issue` when the last issue of an `in issues` one closes); `cardinal run release` adds `- Released: v<version>` to a `done` one and moves it to `ROADMAP-done.md` (`roadmap_archive`). A milestone carries no date unless the project gives it one. `cardinal run roadmap` prints the state of every milestone.
A line `- On hold: <reason>` defers a milestone: `cardinal run next-issue` offers none of its issues until it is removed.

## Read and check an SBOM

- Goal: `forewarn` reads a CycloneDX SBOM (JSON), accepts 1.6 and 1.7, flags older versions, and reports the components
  missing the fields the CRA expects (supplier, license, hashes).
- Why: every later step works on the parsed components, and an incomplete SBOM is the first gap a vendor must close.
- State: done
- Issues:
  - [bootstrap_cargo_workspace](issues/done/bootstrap_cargo_workspace.md)
  - [read_cyclonedx_sbom](issues/done/read_cyclonedx_sbom.md)
  - [check_sbom_completeness](issues/done/check_sbom_completeness.md)
  - [cli_check_command](issues/done/cli_check_command.md)
  - [count_a_supplier_given_without_a_name](issues/done/count_a_supplier_given_without_a_name.md)

## Match known vulnerabilities (OSV)

- Goal: the components of an SBOM are matched exactly, by package URL and version, against OSV, and the affected
  components are listed with the vulnerability, its aliases (CVE) and its source.
- Why: OSV indexes vulnerabilities by package and version range, which makes exact matching on an SBOM possible; the
  exploited lists only name CVEs.
- State: done
- Issues:
  - [match_components_against_vulnerabilities](issues/done/match_components_against_vulnerabilities.md)
  - [read_osv_records](issues/done/read_osv_records.md)
  - [fetch_osv_records](issues/done/fetch_osv_records.md)
  - [cli_list_affected_components](issues/done/cli_list_affected_components.md)
  - [group_matches_of_one_vulnerability](issues/done/group_matches_of_one_vulnerability.md)
  - [keep_distinct_cves_in_separate_matches](issues/done/keep_distinct_cves_in_separate_matches.md)
  - [query_the_osv_api](issues/done/query_the_osv_api.md)
  - [lock_the_osv_cache_against_concurrent_runs](issues/done/lock_the_osv_cache_against_concurrent_runs.md)
  - [share_the_osv_cache_lock_between_readers](issues/done/share_the_osv_cache_lock_between_readers.md)
  - [match_large_archives_without_the_cross_product](issues/done/match_large_archives_without_the_cross_product.md)
  - [evaluate_ecosystem_ranges_beyond_semver](issues/done/evaluate_ecosystem_ranges_beyond_semver.md)
  - [evaluate_nuget_and_packagist_ranges](issues/done/evaluate_nuget_and_packagist_ranges.md)

## Flag actively exploited vulnerabilities (KEV, EUVD)

- Goal: the vulnerabilities found are flagged as actively exploited when CISA KEV or the exploited list of EUVD names
  one of their CVE identifiers, with the list and its date as evidence.
- Why: knowing within 24 hours that a shipped dependency is actively exploited is what CRA article 14 starts from.
- State: in issues
- Issues:
  - [flag_exploited_vulnerabilities](issues/done/flag_exploited_vulnerabilities.md)
  - [read_cisa_kev_catalog](issues/done/read_cisa_kev_catalog.md)
  - [read_euvd_exploited_list](issues/done/read_euvd_exploited_list.md)
  - [cli_flag_exploited_matches](issues/done/cli_flag_exploited_matches.md)
  - [compare_cve_ids_ignoring_case_in_matching](issues/done/compare_cve_ids_ignoring_case_in_matching.md)
  - [share_one_definition_of_a_cve_id_in_the_domain](issues/done/share_one_definition_of_a_cve_id_in_the_domain.md)
  - [trim_the_spaces_around_osv_ids_and_aliases](issues/trim_the_spaces_around_osv_ids_and_aliases.md)
  - [refuse_an_osv_record_with_an_empty_id](issues/refuse_an_osv_record_with_an_empty_id.md)

## Compute CRA reporting deadlines

- Goal: from the moment the vendor becomes aware of an actively exploited vulnerability, the domain computes the early
  warning (24 h), notification (72 h) and final report (14 days) deadlines, covered by BDD scenarios.
- Why: a wrong deadline is the costliest bug of the project; it deserves its own milestone and tests.
- State: idea

## Draft the CRA early warning

- Goal: for each affected component, `forewarn` writes a draft CRA early warning with its deadlines, in a format an
  adapter owns so that a change of the regulatory format only touches it.
- Why: a vendor should not write the report from scratch under pressure.
- State: idea

## Proof-of-concept demo

- Goal: a 20-second demo shows the whole run (SBOM, matching, exploited flag, draft early warning) on a real project.
- Why: completes the proof of concept and shows what the tool does without reading the docs.
- State: idea
- Issues:
  - [choose_a_distinct_product_name](issues/done/choose_a_distinct_product_name.md)

## Upload from CI

- Goal: `forewarn` uploads the SBOM and AI-BOM with product, version and date to a Forewarn service, whose URL is set
  by `--endpoint` or an environment variable.
- Why: keeps a vendor's inventory up to date without manual work; only inventories leave the CI, never source code.
- State: idea

## CI integration templates

- Goal: ready-to-use examples run `forewarn` at each release in GitHub Actions and GitLab CI.
- Why: lowers the cost of adoption to a copy-paste.
- State: idea
