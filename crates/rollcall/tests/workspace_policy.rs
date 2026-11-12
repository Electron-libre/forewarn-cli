//! The workspace policy of `CLAUDE.md`: every crate inherits the license and the lints of the workspace root.

use std::fs;
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the crate lives two levels below the workspace root")
        .to_path_buf()
}

fn read_manifest(path: &Path) -> toml::Table {
    let text = fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    text.parse()
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn member_manifests(root: &toml::Table, root_dir: &Path) -> Vec<PathBuf> {
    let members = root["workspace"]["members"]
        .as_array()
        .expect("workspace.members is an array");
    members
        .iter()
        .map(|m| {
            root_dir
                .join(m.as_str().expect("member is a path"))
                .join("Cargo.toml")
        })
        .collect()
}

#[test]
fn the_root_sets_the_license_and_denies_clippy_pedantic() {
    let root = read_manifest(&workspace_root().join("Cargo.toml"));
    let workspace = &root["workspace"];

    assert_eq!(
        workspace["package"]["license"].as_str(),
        Some("MIT OR Apache-2.0")
    );
    let pedantic = &workspace["lints"]["clippy"]["pedantic"];
    assert_eq!(pedantic["level"].as_str(), Some("deny"));
    assert_eq!(pedantic["priority"].as_integer(), Some(-1));
}

#[test]
fn every_crate_inherits_the_license_and_the_lints() {
    let root_dir = workspace_root();
    let root = read_manifest(&root_dir.join("Cargo.toml"));
    let manifests = member_manifests(&root, &root_dir);
    assert!(!manifests.is_empty(), "the workspace has no member");

    for path in manifests {
        let manifest = read_manifest(&path);
        let shown = path.display();
        assert_eq!(
            manifest["package"]["license"]["workspace"].as_bool(),
            Some(true),
            "{shown}: license.workspace = true is missing"
        );
        assert_eq!(
            manifest.get("lints").and_then(|l| l["workspace"].as_bool()),
            Some(true),
            "{shown}: [lints] workspace = true is missing"
        );
    }
}
