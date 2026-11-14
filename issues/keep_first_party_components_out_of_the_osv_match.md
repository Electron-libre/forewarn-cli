---
priority: medium
depends_on: [match_the_components_nested_in_the_product]
why: 'a false match exits 6 and drafts a false early warning, and the OSV API sends the names of private modules out of the CI; no user has hit it yet'
---
# Keep the vendor's own components out of the OSV match

# Goal
The components an SBOM nests under its product (the modules of a Maven project, which `cdxgen` writes there,
SBR-13) and the product that `syft` and `cdxgen` also list among the top-level components are the vendor's own code.
`forewarn match` matches them like any dependency: a private module whose name and version collide with a published
package gets that package's vulnerabilities (exit 6, a false draft early warning), and with `--osv-api` their
ecosystem, name and version leave the CI. Decide which components are first-party and keep them out of the match, or
at least out of the OSV API queries.

# Findings
* Raised by the `high` review of `match_the_components_nested_in_the_product` (2026-11-14).
* `cdxgen` 13.2.0 on a two-module Maven project nests `pkg:maven/<group>/mod-a@1.0?type=jar` and `mod-b` under
  `metadata.component`, with no hash, license nor supplier
  (`crates/forewarn-cyclonedx/tests/fixtures/cdxgen-maven.cdx.json`).
* `cargo-cyclonedx` marks the local package with the qualifier `download_url=file://.`; its binary target nested under
  the product is already skipped (SBR-13).

# Approach
1. Measure how the tools mark first-party components: a `file://` download URL, the group of the product, the
   `scope`, the position under `metadata.component`, the CycloneDX `cdx:` properties.
2. Candidates (can be combined):
   1. the domain flags a component first-party, from a rule of the adapter, and `match` skips it;
   2. only the OSV API query leaves them out, the local archives still matching them;
   3. a flag lists the package URL prefixes of the vendor's own code.

# Specs
* `specs/sbom-reading.md` (a first-party flag), `specs/cli-match.md` (what is matched or sent to the OSV API).

# Resources
* `crates/forewarn-cyclonedx/src/lib.rs` (`flatten`, `purl_base`), `specs/sbom-reading.md` (SBR-11, SBR-13).
* ADR [0006](../docs/adr/0006-query-the-osv-api-as-an-opt-in-source.md): what the OSV API sends out.

# Hints
* A first-party component still belongs in the completeness check: the CRA asks a supplier and a hash of it too.
