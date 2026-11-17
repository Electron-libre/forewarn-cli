//! The release binaries of ADR 0015: the targets `.github/workflows/release.yml` builds are the ones the Install
//! section of `docs/user-guide.md` offers, so the guide never names an archive no release holds, and the ones whose
//! third-party license notices `about.toml` gathers, so each archive holds the notices of its binary.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the crate lives two levels below the workspace root")
        .to_path_buf()
}

fn read(relative: &str) -> String {
    let path = workspace_root().join(relative);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The `target` of each entry of the build matrix: the lines `- target: <triple>`.
fn workflow_targets(workflow: &str) -> BTreeSet<String> {
    workflow
        .lines()
        .filter_map(|line| line.trim().strip_prefix("- target:"))
        .map(|target| target.trim().to_owned())
        .collect()
}

/// The first cell of each row of the tables of the Install section, a target written as code: `` | `<triple>` | ``.
fn guide_targets(guide: &str) -> BTreeSet<String> {
    guide
        .lines()
        .skip_while(|line| *line != "## Install")
        .skip(1)
        .take_while(|line| !line.starts_with("## "))
        .filter_map(|line| line.strip_prefix("| `"))
        .filter_map(|row| row.split_once('`'))
        .map(|(target, _)| target.to_owned())
        .filter(|target| target.matches('-').count() >= 2)
        .collect()
}

#[test]
fn the_user_guide_lists_the_targets_the_release_workflow_builds() {
    let built = workflow_targets(&read(".github/workflows/release.yml"));
    let listed = guide_targets(&read("docs/user-guide.md"));

    assert!(!built.is_empty(), "the release workflow builds no target");
    assert_eq!(listed, built);
}

#[test]
fn the_license_notices_cover_the_targets_the_release_workflow_builds() {
    let built = workflow_targets(&read(".github/workflows/release.yml"));
    let about: toml::Table = read("about.toml").parse().expect("about.toml is TOML");
    let noticed: BTreeSet<String> = about["targets"]
        .as_array()
        .expect("about.toml lists its targets")
        .iter()
        .map(|target| target.as_str().expect("a target is a string").to_owned())
        .collect();

    assert_eq!(noticed, built);
}

/// The `jq` program the release workflow runs on each SBOM `cargo-cyclonedx` writes (ADR 0016).
const COMPLETE_SBOM: &str = ".github/sbom-complete.jq";

/// An SBOM shaped as `cargo-cyclonedx` writes it: a workspace crate and two crates.io crates, one with its `authors`,
/// one without, the latter nested as a component may be. Supplier and hash missing where `cargo-cyclonedx` leaves
/// them out.
const CARGO_CYCLONEDX_SBOM: &str = r#"{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "metadata": {
    "component": {
      "type": "application",
      "bom-ref": "path+file:///work/crates/forewarn#0.2.0",
      "name": "forewarn",
      "version": "0.2.0",
      "purl": "pkg:cargo/forewarn@0.2.0?download_url=file://."
    }
  },
  "components": [
    {
      "type": "library",
      "bom-ref": "path+file:///work/crates/forewarn-domain#0.2.0",
      "name": "forewarn-domain",
      "version": "0.2.0",
      "licenses": [{ "expression": "MIT OR Apache-2.0" }],
      "purl": "pkg:cargo/forewarn-domain@0.2.0?download_url=file://../forewarn-domain"
    },
    {
      "type": "library",
      "bom-ref": "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.229",
      "name": "serde",
      "version": "1.0.229",
      "hashes": [{ "alg": "SHA-256", "content": "4148590afebada386688f18773da617792bf2ef03ffc1e4cbd2b1d45b023e0ba" }],
      "licenses": [{ "expression": "MIT OR Apache-2.0" }],
      "purl": "pkg:cargo/serde@1.0.229",
      "authors": [{ "name": "David Tolnay" }],
      "components": [
        {
          "type": "library",
          "bom-ref": "registry+https://github.com/rust-lang/crates.io-index#clap@4.6.7",
          "name": "clap",
          "version": "4.6.7",
          "hashes": [{ "alg": "SHA-256", "content": "aa8876b300ab35ba921adea3dfd70157a46249b33f95c9084ae5709785478946" }],
          "licenses": [{ "expression": "MIT OR Apache-2.0" }],
          "purl": "pkg:cargo/clap@4.6.7"
        }
      ]
    }
  ]
}"#;

/// The value of the variable `name` the release workflow sets: the line `<name>: <value>`.
fn workflow_env(name: &str) -> String {
    let workflow = read(".github/workflows/release.yml");
    let prefix = format!("{name}:");
    workflow
        .lines()
        .find_map(|line| line.trim().strip_prefix(prefix.as_str()))
        .unwrap_or_else(|| panic!("the release workflow sets no {name}"))
        .trim()
        .to_owned()
}

/// The manufacturer the release workflow names: `{ name, url: [url] }`.
fn manufacturer() -> serde_json::Value {
    serde_json::json!({
        "name": workflow_env("MANUFACTURER"),
        "url": [workflow_env("MANUFACTURER_URL")],
    })
}

/// The hashes of the workspace crates the workflow gives the program: the product and `forewarn-domain`.
const HASHES: &str = r#"{"forewarn": "c5a60f", "forewarn-domain": "fd53c1"}"#;

/// The SBOM completed by the program of the workflow, run with `jq` and the manufacturer of the workflow.
fn complete(sbom: &str, hashes: &str) -> serde_json::Value {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let input = dir.path().join("sbom.cdx.json");
    fs::write(&input, sbom).expect("the SBOM is written");
    let output = Command::new("jq")
        .arg("-f")
        .arg(workspace_root().join(COMPLETE_SBOM))
        .args(["--arg", "manufacturer", &workflow_env("MANUFACTURER")])
        .args([
            "--arg",
            "manufacturer_url",
            &workflow_env("MANUFACTURER_URL"),
        ])
        .args(["--argjson", "hashes", hashes])
        .arg(&input)
        .output()
        .expect("jq runs (present on the GitHub-hosted runners)");
    assert!(
        output.status.success(),
        "jq: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("jq writes JSON")
}

fn component<'a>(sbom: &'a serde_json::Value, pointer: &str) -> &'a serde_json::Value {
    sbom.pointer(pointer)
        .unwrap_or_else(|| panic!("no {pointer} in {sbom}"))
}

#[test]
fn the_completed_sbom_names_the_manufacturer_of_the_product_with_its_hash() {
    let sbom = complete(CARGO_CYCLONEDX_SBOM, HASHES);

    let product = component(&sbom, "/metadata/component");
    assert_eq!(product["manufacturer"], manufacturer());
    assert_eq!(
        product["hashes"],
        serde_json::json!([{ "alg": "SHA-256", "content": "c5a60f" }])
    );
}

#[test]
fn the_completed_sbom_names_the_manufacturer_supplier_of_the_workspace_crates_with_their_hash() {
    let sbom = complete(CARGO_CYCLONEDX_SBOM, HASHES);

    let domain = component(&sbom, "/components/0");
    assert_eq!(domain["supplier"], manufacturer());
    assert_eq!(
        domain["hashes"],
        serde_json::json!([{ "alg": "SHA-256", "content": "fd53c1" }])
    );
}

#[test]
fn the_completed_sbom_names_crates_io_supplier_of_each_registry_crate_nested_or_not() {
    let sbom = complete(CARGO_CYCLONEDX_SBOM, HASHES);
    let crates_io = serde_json::json!({ "name": "crates.io", "url": ["https://crates.io"] });

    let serde = component(&sbom, "/components/1");
    assert_eq!(serde["supplier"], crates_io);
    assert_eq!(
        serde["authors"],
        serde_json::json!([{ "name": "David Tolnay" }])
    );
    assert_eq!(
        component(&sbom, "/components/1/components/0/supplier"),
        &crates_io
    );
}

#[test]
fn forewarn_finds_the_completed_sbom_complete() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let path = dir.path().join("forewarn.cdx.json");
    let sbom = complete(CARGO_CYCLONEDX_SBOM, HASHES);
    fs::write(&path, sbom.to_string()).expect("the completed SBOM is written");

    let check = Command::new(env!("CARGO_BIN_EXE_forewarn"))
        .arg("check")
        .arg(&path)
        .output()
        .expect("forewarn runs");

    assert!(
        check.status.success(),
        "{}",
        String::from_utf8_lossy(&check.stdout)
    );
}

#[test]
fn a_path_crate_outside_the_workspace_keeps_no_supplier_nor_hash() {
    let sbom = complete(CARGO_CYCLONEDX_SBOM, r#"{"forewarn": "c5a60f"}"#);

    let vendored = component(&sbom, "/components/0");
    assert!(vendored.get("supplier").is_none(), "{vendored}");
    assert!(vendored.get("hashes").is_none(), "{vendored}");
}

#[test]
fn the_release_checks_each_sbom_complete_once_completed() {
    let workflow = read(".github/workflows/release.yml");
    let completed = workflow
        .find(&format!("jq -f {COMPLETE_SBOM}"))
        .expect("the release workflow completes the SBOMs");
    let checked = workflow
        .find("-p forewarn -- check")
        .expect("the release workflow checks the SBOMs");

    assert!(
        completed < checked,
        "the SBOM is checked before it is completed"
    );
    assert!(
        !workflow.contains("--allow-incomplete"),
        "the release accepts an incomplete SBOM"
    );
}

#[test]
fn the_user_guide_names_the_manufacturer_the_release_sboms_name() {
    let guide = read("docs/user-guide.md");

    assert!(guide.contains(&format!("`{}`", workflow_env("MANUFACTURER"))));
}
