---
priority: low
depends_on: [run_the_templates_in_ci]
why: 'the GitHub template is run already; the GitLab one only has its options checked, a comfort for the milestone'
---
# Run the GitLab CI template in the tests

# Goal
`examples/ci/gitlab-ci.yml` is run by `cargo test` as `crates/forewarn/tests/ci_template_run.rs` runs the GitHub
Actions template: the `before_script` and `script` lines of its jobs against the binary of the commit, a fixture
product and local feeds, so a change of the CLI or of the template that breaks a vendor's pipeline turns the check red.

# Findings
* `crates/forewarn/tests/ci_templates.rs` checks only that the options the GitLab template gives `forewarn` exist and
  that it installs an archive the release builds; none of its shell runs.
* The GitHub run (issue `run_the_templates_in_ci`) reads the template line by line, runs each `run:` block with
  `bash -e` and only the job's variables, rewrites `forewarn match` with `--osv`, `--kev`, `--euvd` (its `--refresh`
  dropped, refused when nothing is fetched) and `forewarn upload` with `--dry-run`.

# Approach
1. Read the jobs `forewarn-sbom`, `forewarn-match`, `forewarn-upload`: their `script` lists, the variables of GitLab
   they read (`CI_COMMIT_TAG`, `CI_PROJECT_NAME`…), the files passed between them as artifacts.
2. Candidates: share the reading and the running of `ci_template_run.rs` (a module of `tests/common`), or a test of
   its own; GitLab runs each `script` line with `sh` (the `alpine` image), so the lines run with `sh -e`, not `bash`.
3. The same two runs: an actively exploited match (exit 6) and a match not exploited with the upload as a dry run.

# Milestone
CI integration templates

# Resources
* `crates/forewarn/tests/ci_template_run.rs`, `crates/forewarn/tests/fixtures/ci-template/`.
* `examples/ci/gitlab-ci.yml`, `docs/user-guide.md` (In CI).

# Hints
* The installation step (`apk`, the download of the release) is replaced by the binary of the commit, as in the
  GitHub run.
