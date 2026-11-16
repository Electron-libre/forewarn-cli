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
* ADR [0006](../../docs/adr/0006-query-the-osv-api-as-an-opt-in-source.md): what the OSV API sends out.

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
2. [x] Keep first-party components out of the match: `ComponentReason::FirstParty` first in `ComponentPackage::of`
   (so `ecosystems`/`packages` of `main.rs` skip them with no change there), `"first-party"` in both reports;
   verified by a domain test and a new `crates/forewarn/tests/first_party.rs` (the `--osv-api` mirror sees no module,
   `--osv` records naming `mod-a` give no match); makes true VMT-10, MCH-16, MCH-42, MCH-H4. (autonomous)
3. [x] Fixes of the `high` review: SBR-14 narrowed to the nested components of the product's purl type and
   namespace, purls compared parsed (`forewarn_domain::purl` made public), a blank or invalid purl names nothing,
   `to_domain` takes `first_party`; verified by `reading.rs`; makes true SBR-14. (autonomous)

## Decisions
- Mode: autonomous
- Base commit: 9408faaed69c99e1c321dadf30d6b389b91c9854
- First-party rule: nested in the product, or the product's purl base; no `download_url=file:` rule (a path
  dependency may be a vendored copy of a published crate).
- First-party components are kept out of the whole match, reported not evaluated `first-party`.
- No flag to match them anyway (non-goal of MCH).
- After the `high` review (validated by the user, `ok`): a component nested in the product is first-party only when
  its purl has the type and namespace of the product's, so that a bundled third-party library is still matched; no
  first-party component when the product has no valid purl. Finding 6 (`clean_count` by `ComponentRef`) filed as
  `issues/count_each_component_once_in_the_clean_count.md`.
- New CLI tests go in `crates/forewarn/tests/first_party.rs`: `tests/matching.rs` is over the file size limit.
- Code review: 1 findings: `first_party` not read by matching yet; it is deliverable 2 of this plan, not fixed here.

## Deliverable 2
- done: `ComponentReason::FirstParty`, checked first in `ComponentPackage::of`, so a first-party component is
  never matched, fetched for nor queried; `first-party` in both reports; the three specs `accepted`; MCH-H4 reworded
  on the `time` crate the OSV API test mirror serves; README and CLAUDE.md say it.
- checks: project-check green; specs accepted and traced.
- red: MCH-42, MCH-H4: `left: 1 right: 0` (exit code, `time` queried), `"Maven": not cached ... offline` (exit 5);
  VMT-10: `no variant FirstParty`.
- Code review: no findings

## Deliverable 3
- done: high-review fixes: findings 1, 3, 5, 7, 8 fixed; 2 and 4 kept out by decision 1a (a top-level duplicate or
  a child of the top-level product copy stays matched); 6 filed as an issue.
- checks: project-check green; specs accepted, traced; docs: README, CLAUDE.md.
- red: SBR-14: `left: [] right: ["encoded"]`, `left: ["nested", "blank"] right: []` (product without purl).
- Code review: 1 findings: a nested crate of a namespace-less product (Cargo) is flagged first-party; kept, the non-goal of SBR-14 validated with decision 1a.

Done: every deliverable committed; the user agreed to close on 2026-11-16.
