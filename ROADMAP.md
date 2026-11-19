# Roadmap

The planned work of the project, grouped into milestones, in the order they are meant to land: the user orders them.
A milestone becomes issues once it is shaped (`skill:create-issue`); the `priority` and `depends_on` of each issue file order them within a milestone (`cardinal run next-issue`).
States: `idea`, `shaped`, `in issues`, `done` (set by `cardinal run close-issue` when the last issue of an `in issues` one closes); `cardinal run release` adds `- Released: v<version>` to a `done` one and moves it to `ROADMAP-done.md` (`roadmap_archive`). A milestone carries no date unless the project gives it one. `cardinal run roadmap` prints the state of every milestone.
A line `- On hold: <reason>` defers a milestone: `cardinal run next-issue` offers none of its issues until it is removed.

## CI integration templates

- Goal: ready-to-use examples run `forewarn` at each release in GitHub Actions and GitLab CI.
- Why: lowers the cost of adoption to a copy-paste.
- State: done
- Issues:
  - [github_actions_template](issues/done/github_actions_template.md)
  - [gitlab_ci_template](issues/done/gitlab_ci_template.md)
  - [keep_the_templates_on_the_released_version](issues/done/keep_the_templates_on_the_released_version.md)
  - [run_the_templates_in_ci](issues/done/run_the_templates_in_ci.md)
  - [run_the_gitlab_template_in_the_tests](issues/done/run_the_gitlab_template_in_the_tests.md)
