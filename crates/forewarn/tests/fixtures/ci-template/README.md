# The fixtures of the CI template run

The product a run of `examples/ci/github-actions.yml` (`../../ci_template_run.rs`) or of `examples/ci/gitlab-ci.yml`
(`../../ci_gitlab_template_run.rs`) checks, in place of the SBOM `syft` would write, and the OSV record it is matched
against with the OSV records of `forewarn-osv/tests/fixtures`, the KEV catalog and the EUVD list of
`forewarn-exploited/tests/fixtures`.

| File | What it shows |
|---|---|
| `exploited.cdx.json` | `acme-app` 1.2.0 with `log4j-core` 2.14.1, whose `CVE-2021-44228` the KEV fixture names, and `time` 0.1.43 |
| `affected.cdx.json` | `acme-app` 1.2.0 with `time` 0.1.43 only, affected by `RUSTSEC-2020-0071`, a CVE no exploited list names |
| `osv/GHSA-jfh8-c2jp-5v3q.json` | `Log4Shell`, reduced to its id, alias and affected range of `log4j-core` (written, not fetched) |
