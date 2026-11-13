---
priority: medium
depends_on: [evaluate_ecosystem_ranges_beyond_semver]
why: 'the components of NuGet and Packagist still get no verdict from an ECOSYSTEM range, from the archives as from the API'
---
# Evaluate the ECOSYSTEM ranges of NuGet and Packagist

# Goal
The matching now compares the `ECOSYSTEM` ranges of crates.io, npm, Go, PyPI, Maven and RubyGems (VMT-23); those of
`NuGet` and `Packagist` are still reported "range not evaluated" (VMT-10), so a .NET or PHP SBOM gets no affected
verdict from them. The vendor should get one for those components too.

# Findings
* Left out of `issues/done/evaluate_ecosystem_ranges_beyond_semver.md` by its scope decision (2026-11-13): Go, PyPI,
  Maven and RubyGems first, NuGet and Packagist in a follow-up issue.
* The tests that need an `ECOSYSTEM` range not evaluated use `NuGet` today (`crates/forewarn-domain/tests/matching.rs`,
  `crates/forewarn/tests/matching.rs`, the VMT-8, VMT-10 and MCH scenarios).

# Approach
1. NuGet: the ordering of `NuGet.Versioning` (up to four numeric parts, a pre-release compared without regard to
   case, build metadata ignored) as a `Scheme` of `crates/forewarn-domain/src/version.rs`.
2. Packagist: the ordering of Composer (its version normalization, then `version_compare` with the stability
   suffixes `dev`, `alpha`, `beta`, `RC`, `patch`).
3. Move the "range not evaluated" tests and scenarios to an ecosystem still not compared, or to a range of an
   ecosystem VMT-4 does not map.

# Specs
* `specs/vulnerability-matching.md`: VMT-23 amended (two rows), a requirement per ordering, their scenarios.

# Milestone
Match known vulnerabilities (OSV)

# Resources
* `crates/forewarn-domain/src/version.rs`: `VersionOrder`, `Scheme` and the existing orderings.
* `crates/forewarn-domain/src/matching.rs`: the `ECOSYSTEMS` table, whose fourth column names the ordering.
* `crates/forewarn-domain/tests/version_ordering.rs`: the `Package` helpers (`assert_ordered`, `assert_equal`).

# Hints
* Implement the orderings in the domain, no new dependency (decision of the parent issue).

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-13

## Understanding
Give a verdict to the `ECOSYSTEM` ranges of NuGet (`NuGet.Versioning` ordering) and Packagist (Composer normalization,
then `version_compare`), in the domain, with no new dependency. Every ecosystem VMT-4 maps is then compared: the
"range not evaluated" tests and scenarios move to `GIT` ranges. Composer `dev-` branches and aliases stay invalid.

## Plan
1. [x] NuGet: the `NuGet.Versioning` ordering as a `Scheme`; the "range not evaluated" tests (domain and
   `forewarn match`) and scenarios moved to `GIT` ranges; verified by the NuGet scenarios and the moved tests; makes
   true VMT-27, VMT-23 (NuGet row), VMT-8, VMT-10, MCH-2, MCH-16. (autonomous)
2. [x] Packagist: Composer's normalization and `version_compare` as a `Scheme`; verified by the Packagist scenarios;
   makes true VMT-28, VMT-23 (Packagist row); the spec set `accepted`. (autonomous)
3. [x] Docs (README) and the fixes of the `high` review of the whole issue. (autonomous)

## Decisions
- Mode: autonomous
- Base commit: b5c85d4ff9431ac6c5a4b622a0d33e24d6f6ccdb
- Packagist: Composer's normalization before `version_compare` (`1.0` equals `1.0.0.0`), not the raw `version_compare`
  of osv-scanner.
- NuGet: lenient, leading zeros and numbers of any length accepted.

## Deliverable 1: NuGet
- done: `Scheme::NuGet`, the `NuGet.Versioning` ordering (`NuGet` in `crates/forewarn-domain/src/version.rs`); the
  "range not evaluated" tests (domain and `forewarn match`) and scenarios use a `GIT` range; README and CLAUDE.md
  list NuGet among the orderings.

| check | result |
|---|---|
| tests | pass (`cardinal run project-check`) |
| lint | pass |
| specs | pass (`check-specs`), spec `draft` until VMT-28 is traced |
| docs | README, CLAUDE.md |
| code review | low, see below |

- red: VMT-27, VMT-23: `evaluates_an_ecosystem_range_of_nuget_by_nuget_versioning`: the pair of `12.0.3` was
  reported `RangeNotEvaluated`.
- Code review: no findings
- not verified: none
- decisions needed: none

## Deliverable 2: Packagist
- done: `Scheme::Packagist`, Composer's normalization (classical, date and `<n>.x-dev` versions) then the order of
  `version_compare` (`Packagist` in `crates/forewarn-domain/src/version.rs`); the spec `accepted`; README says a
  record with only `GIT` ranges is what stays not evaluated; CLAUDE.md lists Composer.

| check | result |
|---|---|
| tests | pass (`cardinal run project-check`) |
| lint | pass |
| specs | pass (`check-specs`), spec `accepted` |
| docs | README, CLAUDE.md |
| code review | low, see below |

- red: VMT-28, VMT-23: `evaluates_an_ecosystem_range_of_packagist_by_composer`: the pair of `v10.2.0` was reported
  `RangeNotEvaluated`.
- Code review: no findings
- not verified: Composer's `@dev` flag and `as` aliases are refused as invalid (non-goal), not stripped as Composer does
- decisions needed: none

## Deliverable 3: docs and the high review
- done: `ECOSYSTEMS` and `ComponentPackage` hold a `Scheme`, no longer an `Option`; `PhpPart` an enum in the order
  of `version_compare` (derived `Ord`), no rank numbers; `Packagist::parse` borrows instead of copying; README names
  an unreadable version among the reasons not evaluated.

| check | result |
|---|---|
| tests | pass (`cardinal run project-check`) |
| lint | pass |
| specs | pass (`check-specs`) |
| docs | README, doc comments of `matching.rs` |
| code review | high on `b5c85d4..HEAD`: 7 findings; low on this deliverable, see below |

- red: none (refactor and docs, no new behaviour)
- High review, 7 findings:
  1. `stable` read in any case, where Composer keeps a non-lowercase `STABLE` as an unknown word: not fixed, VMT-28
     says "any case" for every stability; too rare to be worth a case-sensitive path.
  2. A NuGet numeric label over `int32` compared as a number, NuGet compares it as text: not fixed, decision
     "NuGet: lenient" of the plan.
  3. NuGet numeric parts over `int32` accepted: not fixed, same decision.
  4. `Option<Scheme>` now always `Some`: fixed.
  5. README list of reasons not evaluated incomplete: fixed (an unreadable version named).
  6. Rank numbers of `version_compare` scattered: fixed (`PhpPart` enum with derived `Ord`).
  7. Copies in `Packagist::parse` and events parsed again per pair: the copy fixed; parsing the events once per
     range concerns every ordering, not this issue.
- VMT-10 and VMT-23 keep the case of an ecosystem VMT-23 does not name: unreachable today, true when VMT-4 grows.
- Code review: no findings
- not verified: none
- decisions needed: none
