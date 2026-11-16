# Roadmap

The planned work of the project, grouped into milestones, in the order they are meant to land: the user orders them.
A milestone becomes issues once it is shaped (`skill:create-issue`); the `priority` and `depends_on` of each issue file order them within a milestone (`cardinal run next-issue`).
States: `idea`, `shaped`, `in issues`, `done` (set by `cardinal run close-issue` when the last issue of an `in issues` one closes); `cardinal run release` adds `- Released: v<version>` to a `done` one and moves it to `ROADMAP-done.md` (`roadmap_archive`). A milestone carries no date unless the project gives it one. `cardinal run roadmap` prints the state of every milestone.
A line `- On hold: <reason>` defers a milestone: `cardinal run next-issue` offers none of its issues until it is removed.

## Upload from CI

- Goal: `forewarn` uploads the SBOM and AI-BOM with product, version and date to a Forewarn service, whose URL is set
  by `--endpoint` or an environment variable.
- Why: keeps a vendor's inventory up to date without manual work; only inventories leave the CI, never source code.
- State: idea

## CI integration templates

- Goal: ready-to-use examples run `forewarn` at each release in GitHub Actions and GitLab CI.
- Why: lowers the cost of adoption to a copy-paste.
- State: idea
