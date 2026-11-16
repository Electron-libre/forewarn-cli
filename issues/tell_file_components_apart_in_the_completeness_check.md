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

# Milestone
Proof-of-concept demo

# Resources
* `crates/forewarn-cyclonedx/src/lib.rs`, `crates/forewarn-domain/src/completeness.rs`, `crates/forewarn/src/report.rs`.
* `crates/forewarn-cyclonedx/tests/fixtures/README.md` (how the fixtures were generated).
* ADR 0002.

# Hints
* The SBOM of the demo also has the product as a `library` component (`pkg:maven/com.example/shop-backend@1.4.0`)
  and its `metadata.component` of type `file`: do not drop the product with the file components.

# Tracking

Done: all deliverables committed.

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-16

## Understanding
`forewarn check` stops judging the file components (CycloneDX type `file`, the manifests `syft` read) and lists them
apart as not checked, out of the counts and of the exit code; the product (`metadata.component`, even of type `file`)
is untouched. Out of scope: `forewarn match`, whose `Not evaluated (no package URL)` stays as it is.
Measure: of the four fixtures only `syft` emits `file` (`/Cargo.lock`, and its `metadata.component`); `cdxgen` and
`cargo-cyclonedx` emit `application` and `library`. BSI TR-03183-2 2.1.0, 3.2.1: executables, archives and logical
components MUST be components, "any other file MAY be represented as a component"; 5.2.2 asks its fields of each
component listed, with no rule per type.

## Plan
1. [x] Read the component type: `Component::file` set from CycloneDX type `file` in the adapter; verified by
   `crates/forewarn-cyclonedx/tests` (syft fixture, a `file` and an unknown type); makes true SBR-15. (autonomous)
2. [x] Leave the files out of the check and report them apart: `CompletenessReport::not_checked`, the human heading
   `Not checked, file components (n):`, the JSON `notChecked` and `componentCount` without them; verified by
   `crates/forewarn/tests/check.rs` (syft fixture, files only, complete packages plus a file) and domain tests;
   makes true SBC-8, SBC-9, CHK-15, CHK-10 (amended row). (autonomous)
3. [x] Fixes of the `high` review: the domain carries why a component is not checked (`NotCheckedReason`) and names
   it by `ComponentRef`; verified by the existing tests; no new requirement. (autonomous)

## Decisions
- Mode: autonomous
- Base commit: dde0527ad3b8152f22639ec20800641655698054
- File components in `check`: listed apart, out of the counts and of the exit code (answer 1 a).
- `forewarn match` unchanged (answer 2 a).
- `crates/forewarn/src/main.rs` (810 lines, over the limit) is not touched: `check(&sbom.components)` keeps its
  signature.

## Deliverable 1
- done: `Component::file` read from CycloneDX type `file` (the type as written: `File` is not a file); the spec drafts
  of the three capabilities committed with it.
- checks: tests pass, clippy clean, `check-specs` clean, docs n/a (the read field shows to no user before
  deliverable 2), code review below.
- red: SBR-15: `left: [("/pom.xml", false), …, ("nested.txt", false)]` against `right: [("/pom.xml", true), …, ("nested.txt", true)]`.
- Code review: 1 findings
  - The doc of `Component::file` said the completeness check leaves it out, which only deliverable 2 does: reworded
    to state what the field is.
- not verified: none.
- decisions needed: none.

## Deliverable 2
- done: the completeness check leaves the file components out and returns them apart; `forewarn check` lists them
  under `Not checked, file components (n):`, the JSON under `notChecked`, `componentCount` counting the checked
  ones; the three specs `accepted`; `README.md` and `CLAUDE.md` updated.
- checks: tests pass, clippy clean, `check-specs` clean, docs updated, code review below.
- red: SBC-8, SBC-9, CHK-15, CHK-10: `left: "3 of 4 components incomplete:"` against `right: "3 of 3 components incomplete:"`
  (and `notChecked` absent from the JSON report).
- Code review: no findings
- not verified: none.
- decisions needed: none.

## High review (dde0527..HEAD): 6 findings
- `forewarn match` still lists the file components under `Not evaluated`: kept, decision 2 a.
- `componentCount` counts the checked components in `check` and every component in `match`, a change of meaning for
  `check`: kept, the validated amendment of CHK-10, `notChecked` naming what is left out.
- A file the product ships, of type `file`, is no longer checked: kept, the non-goal of `specs/sbom-completeness.md`
  (nothing in the SBOM tells a shipped file from a manifest read).
- The reason `"file"` was hard-coded in the CLI: fixed in deliverable 3, `NotCheckedReason` in the domain, matched
  exhaustively by both reports.
- `NotCheckedComponent` duplicated `ComponentRef`: fixed in deliverable 3.

## Deliverable 3
- done: the fixes of the `high` review above.
- checks: tests pass, clippy clean, `check-specs` clean, docs n/a (no change of behaviour), code review below.
- red: none (a refactor under the green tests).
- Code review: no findings
- not verified: none.
- decisions needed: none.
