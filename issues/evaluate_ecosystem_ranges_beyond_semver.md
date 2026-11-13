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
* Raised by the `high` review of `issues/query_the_osv_api.md` (2026-11-13): with `--osv-api`, the OSV API already
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
