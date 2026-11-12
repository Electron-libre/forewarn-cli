//! The workspace policy of `CLAUDE.md` and ADR 0001: every crate inherits the license and the lints of the workspace
//! root, and the domain crate depends on no other crate of the workspace.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const DOMAIN: &str = "rollcall-domain";

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

/// The members as Cargo resolves them (globs and `exclude` included): `(name, manifest path)`.
fn members() -> Vec<(String, PathBuf)> {
    let output = Command::new(env!("CARGO"))
        .args([
            "metadata",
            "--no-deps",
            "--format-version",
            "1",
            "--offline",
        ])
        .current_dir(workspace_root())
        .output()
        .expect("cargo metadata runs");
    assert!(
        output.status.success(),
        "cargo metadata: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("cargo metadata prints JSON");
    metadata["packages"]
        .as_array()
        .expect("packages is an array")
        .iter()
        .map(|p| {
            (
                p["name"].as_str().expect("name").to_owned(),
                PathBuf::from(p["manifest_path"].as_str().expect("manifest_path")),
            )
        })
        .collect()
}

/// `table.a.b…`, or `None` as soon as a key is missing or not a table.
fn lookup<'a>(table: &'a toml::Table, keys: &[&str]) -> Option<&'a toml::Value> {
    let (last, path) = keys.split_last()?;
    let mut current = table;
    for key in path {
        current = current.get(*key)?.as_table()?;
    }
    current.get(*last)
}

#[test]
fn the_root_sets_the_license_and_denies_clippy_pedantic() {
    let root = read_manifest(&workspace_root().join("Cargo.toml"));

    assert_eq!(
        lookup(&root, &["workspace", "package", "license"]).and_then(toml::Value::as_str),
        Some("MIT OR Apache-2.0")
    );
    let pedantic = ["workspace", "lints", "clippy", "pedantic"];
    let field = |key| {
        let mut keys = pedantic.to_vec();
        keys.push(key);
        lookup(&root, &keys).cloned()
    };
    assert_eq!(field("level"), Some(toml::Value::from("deny")));
    assert_eq!(field("priority"), Some(toml::Value::from(-1)));
}

#[test]
fn every_crate_inherits_the_license_and_the_lints() {
    let members = members();
    assert!(!members.is_empty(), "the workspace has no member");

    for (_, path) in members {
        let manifest = read_manifest(&path);
        let shown = path.display();
        assert_eq!(
            lookup(&manifest, &["package", "license", "workspace"]).and_then(toml::Value::as_bool),
            Some(true),
            "{shown}: license.workspace = true is missing"
        );
        assert_eq!(
            lookup(&manifest, &["lints", "workspace"]).and_then(toml::Value::as_bool),
            Some(true),
            "{shown}: [lints] workspace = true is missing"
        );
    }
}

#[test]
fn the_domain_depends_on_no_other_crate_of_the_workspace() {
    let members = members();
    let (_, path) = members
        .iter()
        .find(|(name, _)| name == DOMAIN)
        .expect("the domain crate is a member");
    let manifest = read_manifest(path);

    for section in ["dependencies", "build-dependencies"] {
        let Some(dependencies) = manifest.get(section).and_then(toml::Value::as_table) else {
            continue;
        };
        for (name, _) in &members {
            assert!(
                !dependencies.contains_key(name),
                "{DOMAIN} depends on {name} in [{section}]: the domain must not depend on an adapter"
            );
        }
    }
}
