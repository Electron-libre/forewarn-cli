---
id: VOR
status: accepted
adrs: []
---

# Version ordering

## Intent

Compare the versions of an `ECOSYSTEM` range of an OSV record in the ordering of its ecosystem, so that matching
(`specs/vulnerability-matching.md`, VMT-9) tells whether a component's version lies in the range as that ecosystem's
own tools would.

## Requirements

### Behaviour

- **VOR-1** (deterministic) The versions of an `ECOSYSTEM` range must be compared by the ordering of its ecosystem in
  this table; a range of an ecosystem the table does not name is not evaluated (VMT-10).

  | Ecosystem | Ordering |
  |---|---|
  | `crates.io`, `npm`, `Go` | Semantic Versioning 2.0, a leading `v` ignored |
  | `PyPI` | PEP 440 (VOR-2) |
  | `Maven` | Maven (VOR-3) |
  | `RubyGems` | RubyGems (VOR-4) |
  | `NuGet` | NuGet (VOR-5) |
  | `Packagist` | Composer (VOR-6) |

### Contract

- **VOR-2** (deterministic) A `PyPI` version must be read and ordered by PEP 440: its normalized forms accepted (any
  case, a leading `v`, the separators `.`, `-`, `_` or none before a pre-release, post-release or dev segment, the
  spellings `alpha`, `beta`, `c`, `pre`, `preview`, `rev`, `r` and the implicit post-release `1.0-1`), the epoch
  compared first, the release compared with its trailing zeros ignored, then a dev release before a pre-release before
  the release before a post-release, and a local version after its public version; a version PEP 440 does not read is
  invalid.
- **VOR-3** (deterministic) A `Maven` version must be ordered by the algorithm of Maven's `ComparableVersion`: items
  split at `.`, a `-` or a change between digits and letters opening a nested list, numbers compared as numbers, the
  null items (zero, the release, an empty list) at the end of each list dropped, a qualifier before a nested list and
  a nested list before a number at the same place, the qualifiers compared without regard to case in the order `alpha` < `beta` <
  `milestone` < `rc` = `cr` < `snapshot` < the release (empty, `ga`, `final`, `release`) < `sp` < any other qualifier
  (by text), `a`, `b` and `m` directly followed by a number read as `alpha`, `beta` and `milestone`; every version is
  valid.
- **VOR-4** (deterministic) A `RubyGems` version must be read and ordered as `Gem::Version` does: each `-` read as
  `.pre.`, segments split at `.` and between digits and letters, the zero segments at the end and those just before
  the first letter segment dropped, numbers compared as numbers, letters as text by byte, a letter segment before a
  number, a version holding letters (a pre-release) before its release; a version that does not match
  `[0-9]+(\.[0-9a-zA-Z]+)*(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?` once trimmed is invalid, an empty one reads as `0`.
- **VOR-5** (deterministic) A `NuGet` version must be read and ordered as `NuGet.Versioning` does by default: once
  trimmed, one to four numeric parts separated by `.` (the missing ones read as `0`, leading zeros accepted), then an
  optional pre-release after the first `-` and build metadata after the first `+`, each made of non-empty labels of
  ASCII letters, digits and `-` separated by `.`; the parts compared as numbers, a version with a pre-release before
  its release, the labels compared in turn (two numeric ones as numbers, a numeric one before any other, two others
  as text without regard to case), a shorter list of labels equal so far first, the build metadata ignored; any other
  version is invalid.
- **VOR-6** (deterministic) A `Packagist` version must be normalized as Composer's `VersionParser` does, then ordered
  by PHP's `version_compare`: once trimmed, build metadata after `+` dropped, a leading `v` ignored, one to four
  numeric parts padded with `.0` to four, or a date version (four digits then two-digit groups), then an optional
  stability `alpha` (`a`), `beta` (`b`), `RC`, `patch` (`pl`, `p`) or `stable`, any case, with its numbers, then an
  optional `dev`; and `<n>.x-dev` branches with each `x` as `9999999`; the normalized versions split into numbers and
  words, compared in turn: numbers as numbers, then `dev` < `alpha` < `beta` < `RC` < a number < `patch`, a version
  that goes on with a number after its prefix after it, one that goes on with a word as the rank of that word against
  a number; any other version (a `dev-` branch among them) is invalid.

## Scenarios

- **VOR-H1** (happy; VOR-1, VOR-2) Given an SBOM with `pkg:pypi/django@2.1` and a record affecting `PyPI` `django` in
  the `ECOSYSTEM` range introduced `0`, fixed `3.0`, when the components are matched, then `django` 2.1 is reported
  as affected.
- **VOR-H2** (happy; VOR-1, VOR-3) Given `pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1` and an `ECOSYSTEM`
  range introduced `2.0-beta9`, fixed `2.15.0`, when it is matched, then it is affected; at `2.15.0` or `2.0-alpha1`
  it is not.
- (VOR-1) Given `pkg:golang/github.com/x/y@v1.2.2` and an `ECOSYSTEM` range introduced `0`, fixed `1.2.3`, when it
  is matched, then it is affected; at `v1.2.3` it is not.
- (VOR-1, VOR-2) Given `pkg:pypi/django@2.1` and an `ECOSYSTEM` range introduced `0`, fixed `3.0`, when it is
  matched, then it is affected; at `3.0.0` or `3.0.post1` it is not, at `3.0rc1` or `3.0.dev2` it is.
- (VOR-2) Given the `PyPI` versions `1.0.dev1`, `1.0a1`, `1.0b2.post3`, `1.0c1`, `1.0`, `1.0+local.7`, `1.0.post1`,
  `1!0.5`, when they are ordered, then they come in this order; `1.0-ALPHA.1` equals `1.0a1`, `v1.0-1` equals
  `1.0.post1`.
- (VOR-2, VMT-10) Given a `PyPI` component at `not a version` and an `ECOSYSTEM` range naming its package, when it is
  matched, then the pair is reported as invalid version.
- (VOR-3) Given the `Maven` versions `1-alpha-1`, `1-beta2`, `1-milestone`, `1-RC1`, `1-SNAPSHOT`, `1`, `1-sp`,
  `1-xyz`, `1.0.1`, `1.1`, when they are ordered, then they come in this order; `1.0.0`, `1-ga`, `1-final` and
  `1-release` equal `1`, `1-cr1` equals `1-rc1`, `1-a1` equals `1-alpha-1`.
- (VOR-3) Given `1.foo` and `1-foo`, or `1-0-1` and `1-1`, when they are ordered, then the first comes before the
  second (a qualifier before a nested list, a nested list before a number).
- (VOR-1, VOR-4) Given `pkg:gem/rails@1.9` and an `ECOSYSTEM` range introduced `0`, fixed `1.10`, when it is
  matched, then it is affected; at `1.10.0` it is not, at `1.10.0.rc1` it is.
- (VOR-4) Given the `RubyGems` versions `1.0.a`, `1.0.a1`, `1.0.b`, `1.0-pre`, `1.0`, `1.0.1`, when they are
  ordered, then they come in this order; `1.0.0` equals `1`, and `1.0 beta` and `1a` are invalid versions.
- (VOR-1, VOR-5) Given `pkg:nuget/Newtonsoft.Json@12.0.3` and an `ECOSYSTEM` range introduced `0`, fixed
  `13.0.1`, when it is matched, then it is affected; at `13.0.1.0` it is not, at `13.0.1-beta1` it is.
- (VOR-5) Given the `NuGet` versions `1.0.0-alpha`, `1.0.0-alpha.1`, `1.0.0-alpha.beta`, `1.0.0-beta.2`,
  `1.0.0-beta.11`, `1.0.0-rc.1`, `1.0.0`, `1.0.0.1`, `1.0.1`, when they are ordered, then they come in this order;
  `1.0` equals `1.0.0.0`, `1.0.0-BETA` equals `1.0.0-beta`, `1.0.0+abc` equals `1.0.0`, and `v1.0`, `1.0.0.0.0` and
  `1.0.0-` are invalid versions.
- (VOR-1, VOR-6) Given `pkg:composer/laravel/framework@v10.2.0` and an `ECOSYSTEM` range introduced `0`, fixed
  `10.2.1`, when it is matched, then it is affected; at `10.2.1.0` it is not, at `10.2.1-RC1` it is.
- (VOR-6) Given the `Packagist` versions `1.0-dev`, `1.0-alpha1`, `1.0-beta`, `1.0-beta2`, `1.0-RC1`, `1.0`,
  `1.0-patch1`, `1.0.1`, `1.x-dev`, `2.0`, when they are ordered, then they come in this order; `1.0` equals
  `v1.0.0.0`, `1.0b2` equals `1.0-beta.2`, `1.0+build` equals `1.0`, and `dev-main` and `1.0-foo` are invalid
  versions.

## Non-goals

- The orderings of the ecosystems VMT-4 does not map: matching does not name their packages.
- Composer's `dev-` branches and aliases (`1.0 as 2.0`, `@dev`): they name no point of an ordering.
- The OSV algorithm of a range (its events, `introduced`, `fixed`, `last_affected`): VMT-9 states it, this spec only
  orders the versions it compares.
