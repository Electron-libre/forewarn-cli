# Roadmap

The planned work of the project, grouped into milestones, in the order they are meant to land: the user orders them.
A milestone becomes issues once it is shaped (`skill:create-issue`); the `priority` and `depends_on` of each issue file order them within a milestone (`cardinal run next-issue`).
States: `idea`, `shaped`, `in issues`, `done` (set by `cardinal run close-issue` when the last issue of an `in issues` one closes); `cardinal run release` adds `- Released: v<version>` to a `done` one and moves it to `ROADMAP-done.md` (`roadmap_archive`). A milestone carries no date unless the project gives it one. `cardinal run roadmap` prints the state of every milestone.
A line `- On hold: <reason>` defers a milestone: `cardinal run next-issue` offers none of its issues until it is removed.



## Read and check an SBOM

- Goal: `rollcall` reads a CycloneDX SBOM (JSON), accepts 1.6 and 1.7, flags older versions, and reports the components
  missing the fields the CRA expects (supplier, license, hashes).
- Why: every later step works on the parsed components, and an incomplete SBOM is the first gap a vendor must close.
- State: idea

## Match exploited vulnerabilities

- Goal: the components of an SBOM are matched exactly against public lists of actively exploited vulnerabilities
  (CISA KEV, EUVD, OSV), and the affected components are listed with the vulnerability and its source.
- Why: knowing within 24 hours that a shipped dependency is actively exploited is what CRA article 14 starts from.
- State: idea

## Draft the CRA early warning

- Goal: for each affected component, `rollcall` writes a draft CRA early warning with its 24 h / 72 h / 14-day deadlines,
  and a 20-second demo shows the whole run on a real project.
- Why: a vendor should not write the report from scratch under pressure; this completes the proof of concept.
- State: idea

## Upload from CI

- Goal: `rollcall` runs in CI at each release and uploads the SBOM and AI-BOM with product, version and date to a
  Rollcall service, whose URL is set by `--endpoint` or an environment variable.
- Why: keeps a vendor's inventory up to date without manual work.
- State: idea
