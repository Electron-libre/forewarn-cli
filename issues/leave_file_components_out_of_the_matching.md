---
priority: low
why: 'a file component rarely carries a package URL, but when it does it can be reported as an affected package'
---
# Leave the file components out of the matching

# Goal
The reading tells the file components apart (SBR-15: a manifest or a lock file a tool read, CycloneDX type `file`),
and the completeness check already treats them apart, but the matching does not: a file component that carries a
package URL is matched like a package, and can be reported affected by the vulnerabilities of the package it names.
Expected outcome: the matching sets a file component apart with a reason of its own, as it does for the first-party
components, and never matches it.

# Findings
* 2026-11-19, tag `v0.3.0`: in `forewarn-domain`, only `completeness.rs` reads `Component::file`;
  `ComponentPackage::of` returns `ComponentReason::FirstParty` for a first-party component and has no case for a
  file, so `match_components` matches a file component whose package URL it can place.
* The table of VMT-10 has a `first-party` reason, applied before the others; it has none for a file.

# Approach
1. A `file` reason in the table of VMT-10 (applied before the reasons on the package URL, like `first-party`) and a
   `ComponentReason` variant for it in `ComponentPackage::of`; or leave the file components out of the report
   entirely, not even counted as not evaluated: decide at step 1.
2. The report of the CLI shows the new reason like the others.
3. A release under a new tag, so the crates that depend on `forewarn-domain` by tag can take it.

# Specs
* `specs/vulnerability-matching.md`: VMT-10 amended (a reason, or a new requirement leaving the files out), VMT-11.

# Resources
* `crates/forewarn-domain/src/matching.rs` (`ComponentPackage::of`, `ComponentReason`), `completeness.rs` (how the
  files are set apart there).
* `specs/vulnerability-matching.md` (VMT-10, VMT-11), `specs/sbom-reading.md` (SBR-14, SBR-15).
