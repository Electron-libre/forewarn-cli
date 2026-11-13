---
priority: medium
why: 'the components of PyPI, Maven and the other ecosystems VMT-9 does not compare get no verdict, from the archives as from the API'
---
# Evaluate the ECOSYSTEM ranges of the ecosystems that are not Semantic Versioning

# Goal
The matching evaluates an `ECOSYSTEM` range only for `crates.io` and `npm` (VMT-9); for every other ecosystem
(PyPI, Maven, RubyGems, NuGet, Packagist, Go when its records use `ECOSYSTEM`) the pair is reported "range not
evaluated" (VMT-10). An SBOM of those ecosystems then gets no affected verdict and `forewarn match` exits with 0, even
when a record names the exact version through a range. The vendor should get a verdict for those components too.

# Findings
* Raised by the `high` review of `issues/done/query_the_osv_api.md` (2026-11-13): with `--osv-api`, the OSV API already
  returns only the records it considers affecting each version, and the domain still lists them as not evaluated
  for these ecosystems; the same records read from an archive are reported the same way.
* VMT-10 forbids counting a pair not evaluated as unaffected, so the gap is shown, never hidden: it is a missing
  verdict, not a false negative of the report.

# Approach
1. Compare the versions of each ecosystem with its own ordering, ecosystem by ecosystem, in the domain: PEP 440 for
   PyPI, the Maven ordering, RubyGems versions; each a deliverable with its scenarios. Check the licences of any
   crate used (no copyleft).
2. Or, for `--osv-api` only, report a record the API returned for a version as affecting it on the API's word, marked
   as such in the report: simpler, but the verdict then depends on the API and not on the domain (`CLAUDE.md`:
   deterministic matching).
3. Measure first which ecosystems the SBOMs of the target users hold, to order the ecosystems of option 1.

# Specs
* `specs/vulnerability-matching.md`: VMT-9 amended (the ecosystems compared), new scenarios per ecosystem.

# Milestone
Match known vulnerabilities (OSV)

# Resources
* `crates/forewarn-domain/src/matching.rs`: `SEMVER_ECOSYSTEMS`, the range evaluation.
* `specs/vulnerability-matching.md` (VMT-9, VMT-10), `specs/cli-match.md` (MCH-2, MCH-24).
* ADR 0006 (`docs/adr/0006-query-the-osv-api-as-an-opt-in-source.md`): the API filters the records by version itself.

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-13

## Understanding
Give a verdict to the `ECOSYSTEM` ranges of Go, PyPI, Maven and RubyGems by comparing their versions with each
ecosystem's own ordering, in the domain (option 1; option 2 refused: the verdict stays the domain's). NuGet and
Packagist are out of scope, left for a follow-up issue; their ranges stay "range not evaluated".

## Plan
1. [x] Ordering per ecosystem, and Go: a domain module giving each ecosystem its version ordering, `in_range` generic
   over it; `Go` compared by Semantic Versioning; the not-evaluated tests move from PyPI to NuGet; verified by the
   domain tests of the Go and NuGet scenarios; makes true VMT-9, VMT-10, VMT-23 (Go row). (autonomous)
2. [x] PyPI: PEP 440 parsing and ordering; verified by the PyPI scenarios, one through `forewarn match`; makes true
   VMT-24, VMT-23 (PyPI row). (autonomous)
3. [ ] Maven: the `ComparableVersion` ordering; verified by the Maven scenarios; makes true VMT-25, VMT-23 (Maven row).
4. [ ] RubyGems: the `Gem::Version` ordering; verified by the RubyGems scenarios; makes true VMT-26, VMT-23 (RubyGems
   row); the spec set `accepted`.
5. [ ] Docs and the fixes of the `high` review of the whole issue; a follow-up issue for NuGet and Packagist.

## Decisions
- Mode: autonomous
- Base commit: 0967ac7098626574152748006687a65247a9db8b
- Version orderings: implemented in the domain, no new dependency (PEP 440, Maven, RubyGems).
- Scope: Go, PyPI, Maven, RubyGems in this order; NuGet and Packagist in a follow-up issue.

## Deliverable 1: ordering per ecosystem, and Go
- done: module `version` of the domain (`VersionOrder`, `Scheme`), `in_range` generic over the ordering; `Go`
  `ECOSYSTEM` ranges compared by Semantic Versioning; the "range not evaluated" tests and the MCH scenario use NuGet.

| check | result |
|---|---|
| tests | pass (`cardinal run project-check`) |
| lint | pass |
| specs | pass (`check-specs`) |
| docs | `specs/cli-match.md` scenario moved to NuGet; README unchanged until the last ordering |
| code review | low, see below |

- red: VMT-9, VMT-23: `evaluates_an_ecosystem_range_of_go_by_semantic_versioning`: the pair of `v1.2.2` was reported
  `RangeNotEvaluated`.
- Code review: no findings
- not verified: none
- decisions needed: none

## Deliverable 2: PyPI
- done: `Pep440` ordering in the module `version` (epoch, release without trailing zeros, dev/pre/post, local
  segments, numbers of any length); `PyPI` `ECOSYSTEM` ranges evaluated; the VMT-8 test and scenario moved to NuGet.

| check | result |
|---|---|
| tests | pass (`cardinal run project-check`) |
| lint | pass |
| specs | pass (`check-specs`) |
| docs | VMT-8 scenario in `specs/vulnerability-matching.md`; README unchanged until the last ordering |
| code review | low, see below |

- red: VMT-9, VMT-23, VMT-24: `evaluates_an_ecosystem_range_of_pypi_by_pep_440` and the ordering tests: the pair of
  `django` 2.1 was reported `RangeNotEvaluated`; `forewarn match` exited with 0 instead of 1.
- Code review: no findings
- not verified: none
- decisions needed: none
