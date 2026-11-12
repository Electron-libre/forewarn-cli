---
priority: high
why: 'the exact matching is the core of the milestone; every other issue of it feeds or prints it'
---
# Match the components of an SBOM against known vulnerabilities

# Goal
The domain must tell, for each component of an SBOM, which known vulnerabilities affect it, by exact matching of its
package URL (ecosystem and name) and version against the affected packages and version ranges of each vulnerability.
The result lists each affected component with the vulnerability, its aliases (CVE) and its source, deterministically
and with no I/O.

# Findings
* `forewarn_domain::sbom::Component` already carries `purl` and `version` as written in the SBOM; nothing parses the
  package URL yet.
* The domain has no vulnerability type yet; `forewarn-domain/src/lib.rs` announces vulnerability matching in its doc.

# Approach
1. Domain types for a vulnerability as matching needs it, shaped after the OSV schema but owned by the domain: id,
   aliases, source, affected packages (ecosystem, name), their explicit `versions` and their ranges (`SEMVER`,
   `ECOSYSTEM`, with `introduced`, `fixed`, `last_affected` events).
2. Parse the package URL of a component into a type and a name (namespace included), mapped to an OSV ecosystem
   (`cargo` to `crates.io`, `npm`, `pypi` to `PyPI`…); a component without a purl or a version is not matched, and
   the result says so.
3. Version comparison: start with the semver ecosystems (crates.io, npm) and the explicit `versions` list, which is
   exact in every ecosystem; a range in an ecosystem whose ordering is not implemented is reported as not evaluated,
   never guessed. PEP 440, Maven and the others come in later issues.
4. A pure function from the components and the vulnerabilities to the matches, ordered deterministically.

# Specs
* `specs/vulnerability-matching.md` (to write at step 1): the purl mapping, the version rules, what is not evaluated.

# Milestone
Match known vulnerabilities (OSV)

# Resources
* `CLAUDE.md`: hexagonal architecture, deterministic matching.
* `crates/forewarn-domain/src/sbom.rs`: the component type.
* OSV schema (`affected`, `ranges`, `events`, `versions`) and the package URL specification (purl types).
* The SBOM fixtures of `crates/forewarn-cyclonedx/tests/fixtures/` (their purls show what real tools write).

# Hints
* The domain depends on no adapter: the OSV JSON is read by `read_osv_records`, not here.
* A purl may carry qualifiers and a subpath, and its name is percent-encoded; the version of the component may differ
  from the version in the purl, so settle which one wins at step 1.
* Semver pre-releases and build metadata change the ordering; OSV `SEMVER` ranges follow semver 2.0.
