---
priority: high
depends_on: [github_actions_template]
why: 'the other half of the milestone goal; reuses the steps and the exit code choices settled for GitHub Actions'
---
# Provide a GitLab CI template

# Goal
A vendor on GitLab runs `forewarn` at each release by including or copying one file, with the same steps and the same
failure policy as the GitHub Actions template: install a pinned and checked release, produce the SBOM, check, match
with the report and the drafts as artifacts, upload on a tag.

# Approach
1. A file `examples/ci/gitlab-ci.yml`, each job commented: `cache:key` on the day for the `--cache` directory,
   `artifacts:when: always` for the report and `drafts/`, `rules` on `$CI_COMMIT_TAG` for the upload,
   `FOREWARN_ENDPOINT` and `FOREWARN_TOKEN` as masked CI/CD variables.
2. Candidates for the image: a plain image with `curl` and the static musl binary (no Rust toolchain), or the `syft`
   image with `forewarn` installed in it; decided at step 1.
3. The section "In CI" of the user guide points to it next to the GitHub Actions one.
4. The test of the GitHub template extended to this file: the commands and options it uses exist.

# Milestone
CI integration templates

# Resources
* `issues/github_actions_template.md` (or `issues/done/` once closed): the steps and choices to mirror.
* `docs/user-guide.md`: sections "Install", "The cache", "In CI", "Exit codes".

# Hints
* GitLab caches are keyed per runner unless a distributed cache is set; say so in a comment rather than promise one
  download a day.
* A masked variable must meet GitLab's masking rules; a token that does not is printed in clear in the logs if echoed.
