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
* `issues/done/github_actions_template.md` (or `issues/done/` once closed): the steps and choices to mirror.
* `docs/user-guide.md`: sections "Install", "The cache", "In CI", "Exit codes".

# Hints
* GitLab caches are keyed per runner unless a distributed cache is set; say so in a comment rather than promise one
  download a day.
* A masked variable must meet GitLab's masking rules; a token that does not is printed in clear in the logs if echoed.

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-19

## Understanding
`examples/ci/gitlab-ci.yml`, the GitLab twin of the GitHub template: same triggers (a tag `v*`, a pipeline schedule on
the latest tag), same steps and failure policy; the test of the templates covers both, the guide points to it. Out of
scope: running it (no GitLab in this repository's CI), the pinned version at release (its own issue).

## Plan
1. [x] Template, test and guide: `examples/ci/gitlab-ci.yml` with three jobs, `sbom` (checkout of the release, `syft`,
   artifact), `match` (`check`, `match`, cache `when: always`, report and drafts as artifacts `when: always`) and
   `upload` (on a tag, needing `sbom` only, so it runs whatever `match` found), on an `alpine` image with `forewarn`
   and `syft` downloaded and checked against their checksums; `ci_templates.rs` runs its two checks over each template;
   "In CI" of the user guide, `README.md` and `CLAUDE.md` name it; verified by `ci_templates` (red before the file).
   (autonomous)

2. [x] Fixes of the `high` review of the issue: the GitLab file included with no global key, its archives following
   the runner's architecture, `curl --fail-early`, the SBOM kept once, the test listing `examples/ci/`; verified by
   `ci_templates`. (autonomous)

## Decisions
- Mode: autonomous
- Base commit: 2c7c5ddf1f8d7247d9dd0292af71b93a1c49b5a0
- Image `alpine:3`; `syft` downloaded from its release, checked against its checksums file.
- Three jobs: `sbom`, `match` (needs `sbom`), `upload` (needs `sbom` only, on a tag).
- Cache: the fixed key `forewarn-feeds`, `when: always`, in `.forewarn-cache` of the project (GitLab overwrites a
  key and caches paths of the project only).

## Deliverable 1
done: `examples/ci/gitlab-ci.yml`, `ci_templates.rs` over both templates, the guide's "In CI", `README.md`,
`CLAUDE.md`.

| check | result |
|---|---|
| tests | pass (`ci_templates`: 2; a renamed option of the GitLab template, on a continued line too, turns it red) |
| lint | pass |
| specs | n/a (no behaviour of the CLI changes) |
| docs | user guide, README, CLAUDE.md |
| code review | 1 finding, fixed |

red: none traced; `ci_templates`: `examples/ci/gitlab-ci.yml: No such file or directory`.

Code review: 1 finding. Fixed: `syft` was always the amd64 archive, so an ARM64 runner told to switch `TARGET` failed
the `sbom` job; its archive now follows `uname -m`.

not verified: the jobs have not run on GitLab; busybox `sha256sum -c -` and the `syft` asset names are read from
their documentation and release, not run.

## Deliverable 2
done: the fixes of the `high` review (10 findings) in the GitLab template, the GitHub template's download, the test
and the guide.

| check | result |
|---|---|
| tests | pass (`ci_templates`; a GitLab archive off the musl triple turns it red) |
| lint | pass |
| specs | n/a |
| docs | user guide "In CI" |
| code review | 1 finding, fixed |

red: none traced; deliverable of fixes, its test already green.

`high` review: 10 findings. Fixed: the global `workflow`, `stages`, `default` and `variables` that changed the
including project (now an included file, every key on its jobs, stage `test`); the forewarn archive fixed to x86_64
(now `$(uname -m)`, the test checking both architectures); a failed download hidden by the next one
(`--fail-early`, both templates); the SBOM stored twice; the templates listed by hand in the test (now
`examples/ci/*.yml`). Not fixed: the two install sequences kept apart, each downloads another tool and an anchor
would make the example harder to read.

Code review: 1 finding. Fixed: the jobs in the default stage `test`, missing from a project whose `stages:` leaves it
out; `stage: test` now explicit, the file and the guide saying to add it or change it (`.pre` and `.post`, always
defined, would make a scheduled pipeline with these jobs alone invalid).

not verified: the jobs have not run on GitLab.
