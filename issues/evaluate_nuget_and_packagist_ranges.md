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
* Left out of `issues/evaluate_ecosystem_ranges_beyond_semver.md` by its scope decision (2026-11-13): Go, PyPI,
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
