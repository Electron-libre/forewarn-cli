---
priority: medium
depends_on: [github_actions_template, gitlab_ci_template]
why: 'without it the pinned version of the templates goes stale at the next release, but the templates work without it'
---
# Keep the pinned version of the CI templates on the latest release

# Goal
The CI templates pin a release of `forewarn`. At each release, that version moves with the workspace version, so a
vendor copying a template always gets the latest release, and a forgotten update fails the project check rather than
reaching users.

# Findings
* `just set-version <version>` writes `[workspace.package] version` and `Cargo.lock`, and is the
  `release_version_command` that `cardinal run release` runs.
* `crates/forewarn/tests/workspace_policy.rs` checks that the workspace version is the newest release of `CHANGELOG.md`.

# Approach
1. `just set-version` also rewrites the pinned version in `examples/ci/*.yml` (one marked line or variable per file).
2. A test checks that each template pins the workspace version, next to the changelog check.
3. Alternative: the templates download `releases/latest` and only comment how to pin; weighed at step 1 against
   reproducible builds.

# Milestone
CI integration templates

# Resources
* `justfile`: the recipe `set-version`.
* `crates/forewarn/tests/workspace_policy.rs`: `the_workspace_version_is_the_newest_release_of_the_changelog`.
* `.claude/cardinal.toml`: `release_version_command`.

# Hints
* The version is written before the release exists: the pinned URL only resolves once the tag's workflow publishes,
  which is fine for a template read from the tagged commit.
