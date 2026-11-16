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

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-16

## Understanding
The adapter flags a component first-party when the SBOM nests it in the product or its package URL (without
qualifiers nor subpath) is the product's; matching then reports it not evaluated, `first-party`, so it is never
matched, its ecosystem never fetched for it alone, and never sent to the OSV API. It stays in the completeness check.
Measured: `cdxgen` Maven nests the modules under the product; `cdxgen` Cargo lists the product at the top level with
its purl; `syft` lists it with no purl (already not evaluated); `cargo-cyclonedx` lists only deps at the top level.

## Plan
1. [ ] Read the first-party flag: `Component::first_party` in the domain, set by the CycloneDX adapter (nested in the
   product, or the product's purl base); verified by `crates/forewarn-cyclonedx/tests/reading.rs` and
   `real_tools.rs` (cdxgen Maven and Cargo fixtures); makes true SBR-14, SBR-H5.
2. [ ] Keep first-party components out of the match: `ComponentReason::FirstParty` first in `ComponentPackage::of`
   (so `ecosystems`/`packages` of `main.rs` skip them with no change there), `"first-party"` in both reports;
   verified by a domain test and a new `crates/forewarn/tests/first_party.rs` (the `--osv-api` mirror sees no module,
   `--osv` records naming `mod-a` give no match); makes true VMT-10, MCH-16, MCH-42, MCH-H4.

## Decisions
- Mode: autonomous
- Base commit: 9408faaed69c99e1c321dadf30d6b389b91c9854
- First-party rule: nested in the product, or the product's purl base; no `download_url=file:` rule (a path
  dependency may be a vendored copy of a published crate).
- First-party components are kept out of the whole match, reported not evaluated `first-party`.
- No flag to match them anyway (non-goal of MCH).
- New CLI tests go in `crates/forewarn/tests/first_party.rs`: `tests/matching.rs` is over the file size limit.
- Code review: 1 findings: `first_party` not read by matching yet; it is deliverable 2 of this plan, not fixed here.
