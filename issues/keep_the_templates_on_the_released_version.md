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

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-19

## Understanding
Keep the `FOREWARN_VERSION` the CI templates pin equal to the workspace version: `just set-version` rewrites it, a test
fails when they differ. Pinning stays (approach 1): a copied template installs one release, reproducibly, and the
`releases/latest` alternative is dropped. No spec: release tooling, not a capability of the CLI.

## Plan
1. [x] Pin the templates on the workspace version: `just set-version` rewrites the one `FOREWARN_VERSION: X.Y.Z` line of
   each `examples/ci/*.yml` and checks it wrote it; a test of `workspace_policy.rs` checks that each template has exactly
   one such line and that it is the workspace version; CLAUDE.md and the user guide say so; verified by that test (red
   against a template edited to another version) and a `just set-version` run on a scratch copy. (autonomous)

## Decisions
- Mode: autonomous
- Approach: pinned version rewritten by `set-version`, not `releases/latest` (reproducible builds, checksums of a known
  release).
- Base commit: ca3fa41f9c84b02a120b8d5e2a131fa22cd5ca02

## Summary of deliverable 1
- done: `just set-version` rewrites and checks the one `FOREWARN_VERSION` line of each `examples/ci/*.yml`; the test
  `each_ci_template_pins_the_workspace_version` checks each template pins the workspace version; CLAUDE.md, the user
  guide and the test's module doc say so.
- red: none (no spec): `examples/ci/github-actions.yml must pin the workspace version on one FOREWARN_VERSION: X.Y.Z
  line: run just set-version <version>` (left ["0.3.0"], right ["0.4.0"]).
- Verified: `just set-version 0.9.1` on a scratch copy wrote 0.9.1 in both templates and `Cargo.toml`.
- Code review: no findings
