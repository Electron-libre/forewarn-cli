# Roadmap archive

The released milestones, moved out of the roadmap by `release`, oldest first.

## Read and check an SBOM

- Goal: `forewarn` reads a CycloneDX SBOM (JSON), accepts 1.6 and 1.7, flags older versions, and reports the components
  missing the fields the CRA expects (supplier, license, hashes).
- Why: every later step works on the parsed components, and an incomplete SBOM is the first gap a vendor must close.
- State: done
- Released: v0.1.0
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
- Released: v0.1.0
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
- State: done
- Released: v0.1.0
- Issues:
  - [flag_exploited_vulnerabilities](issues/done/flag_exploited_vulnerabilities.md)
  - [read_cisa_kev_catalog](issues/done/read_cisa_kev_catalog.md)
  - [read_euvd_exploited_list](issues/done/read_euvd_exploited_list.md)
  - [cli_flag_exploited_matches](issues/done/cli_flag_exploited_matches.md)
  - [compare_cve_ids_ignoring_case_in_matching](issues/done/compare_cve_ids_ignoring_case_in_matching.md)
  - [share_one_definition_of_a_cve_id_in_the_domain](issues/done/share_one_definition_of_a_cve_id_in_the_domain.md)
  - [trim_the_spaces_around_osv_ids_and_aliases](issues/done/trim_the_spaces_around_osv_ids_and_aliases.md)
  - [refuse_an_osv_record_with_an_empty_id](issues/done/refuse_an_osv_record_with_an_empty_id.md)
  - [group_no_records_by_an_empty_id_in_the_domain](issues/done/group_no_records_by_an_empty_id_in_the_domain.md)

## Compute CRA reporting deadlines

- Goal: the domain computes the early warning (24 h) and notification (72 h) deadlines from the moment the vendor
  becomes aware of an actively exploited vulnerability, and the final report deadline (14 days) from the moment a
  corrective or mitigating measure is available (CRA article 14(2)), covered by BDD scenarios.
- Why: a wrong deadline is the costliest bug of the project; it deserves its own milestone and tests.
- State: done
- Released: v0.1.0
- Issues:
  - [compute_cra_reporting_deadlines](issues/done/compute_cra_reporting_deadlines.md)
  - [cli_print_reporting_deadlines](issues/done/cli_print_reporting_deadlines.md)
  - [tell_overdue_reporting_deadlines](issues/done/tell_overdue_reporting_deadlines.md)
