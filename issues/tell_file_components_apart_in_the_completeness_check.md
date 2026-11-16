---
priority: medium
depends_on: []
why: 'every syft SBOM reports its manifest files as incomplete components, so the count of incomplete components a vendor acts on is inflated'
---
# Tell the file components of an SBOM apart in the completeness check

# Goal
`syft` lists the manifests it read (`/pom.xml`, `/requirements.txt`, `/Cargo.lock`) as components of type `file`,
with hashes but no supplier, license or package URL. `forewarn check` reports them as incomplete components, next to
the packages, though a vendor cannot and need not give a manifest a supplier. The completeness check should judge
the components a vendor ships, and either leave the file components out or report them apart.

# Findings
* Demo run of 2026-11-16: a Maven and Python project, SBOM by `syft` (`anchore/syft:latest`, CycloneDX 1.6).
* `forewarn check` prints `9 of 9 components incomplete`, two of them `/pom.xml: missing supplier, license` and
  `/requirements.txt: missing supplier, license`, both `"type": "file"` with SHA-1 and SHA-256 hashes.
* `forewarn match` already lists them under `Not evaluated` (`no package URL`), so they also lower `Clean: 2 of 9`.
* The fixture `crates/forewarn-cyclonedx/tests/fixtures/syft.cdx.json` holds such a component (`/Cargo.lock`);
  CHK-H1 describes the `syft` case without saying what happens to it.
* Unknown: whether `cdxgen` or `cargo-cyclonedx` emit file components too, and whether BSI TR-03183-2 expects a
  supplier and a license for them.

# Approach
1. Measure first: list the component types the three tools of the fixtures emit, and read what BSI TR-03183-2
   requires per component type.
2. Read the component type in the CycloneDX adapter (its types stay in the adapter, ADR 0002) and give the domain
   what it needs to tell a file from a package.
3. Then, candidates: leave the file components out of the completeness check and of the counts; or check them
   for a hash only; or report them under a heading of their own, as `match` does for those not evaluated.

# Specs
* `specs/sbom-reading.md` (the component type read), `specs/sbom-completeness.md` (which components are checked),
  `specs/cli-check.md` (CHK-2, CHK-3, CHK-H1), and `specs/cli-match.md` (MCH-3) if the count of clean components
  changes.

# Resources
* `crates/forewarn-cyclonedx/src/lib.rs`, `crates/forewarn-domain/src/completeness.rs`, `crates/forewarn/src/report.rs`.
* `crates/forewarn-cyclonedx/tests/fixtures/README.md` (how the fixtures were generated).
* ADR 0002.

# Hints
* The SBOM of the demo also has the product as a `library` component (`pkg:maven/com.example/shop-backend@1.4.0`)
  and its `metadata.component` of type `file`: do not drop the product with the file components.
