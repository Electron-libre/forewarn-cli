//! The workspace policy of `CLAUDE.md` and ADR 0001: every crate inherits the license and the lints of the workspace
//! root, and the domain crate depends on no other crate of the workspace. Also the version of the last release:
//! `cardinal run release <version>` writes the `CHANGELOG.md` section and, through the `release_version_command` of
//! `.claude/cardinal.toml` (`just set-version`), the `[workspace.package] version` that `forewarn --version` prints.
//! And one license policy: the licenses `deny.toml` allows every dependency are those `about.toml` accepts in the
//! release binaries.

mod common;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const DOMAIN: &str = "forewarn-domain";

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

fn workspace_version() -> String {
    let root = read_manifest(&workspace_root().join("Cargo.toml"));
    lookup(&root, &["workspace", "package", "version"])
        .and_then(toml::Value::as_str)
        .expect("Cargo.toml: [workspace.package] version is a string")
        .to_owned()
}

/// The version of the first `## [X.Y.Z]` heading of `CHANGELOG.md` (`## [Unreleased]` skipped), the newest release.
fn newest_changelog_version() -> Option<String> {
    let path = workspace_root().join("CHANGELOG.md");
    let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    text.lines().find_map(|line| {
        let (version, _) = line.strip_prefix("## [")?.split_once(']')?;
        (version != "Unreleased").then(|| version.to_owned())
    })
}

#[test]
fn the_workspace_version_is_the_newest_release_of_the_changelog() {
    assert_eq!(
        Some(workspace_version()),
        newest_changelog_version(),
        "[workspace.package] version differs from the newest release of CHANGELOG.md: run \
         `just set-version <version>` (the release_version_command of `cardinal run release`)"
    );
}

#[test]
fn the_binary_prints_the_workspace_version() {
    let run = common::run(&["--version"], None);

    assert_eq!(run.code, 0, "{}", run.stderr);
    assert_eq!(run.stdout, format!("forewarn {}\n", workspace_version()));
}

/// The strings of the array at `keys` of a TOML file of the workspace root.
fn string_set(file: &str, keys: &[&str]) -> BTreeSet<String> {
    let table = read_manifest(&workspace_root().join(file));
    lookup(&table, keys)
        .and_then(toml::Value::as_array)
        .unwrap_or_else(|| panic!("{file} has no array {}", keys.join(".")))
        .iter()
        .map(|value| {
            value
                .as_str()
                .unwrap_or_else(|| panic!("{file}: {value} is not a string"))
                .to_owned()
        })
        .collect()
}

#[test]
fn deny_toml_allows_the_licenses_about_toml_accepts() {
    let accepted = string_set("about.toml", &["accepted"]);
    let allowed = string_set("deny.toml", &["licenses", "allow"]);

    assert!(!accepted.is_empty(), "about.toml accepts no license");
    assert_eq!(allowed, accepted);
}

#[test]
fn deny_toml_allows_no_other_license_to_a_single_crate() {
    let accepted = string_set("about.toml", &["accepted"]);
    let deny = read_manifest(&workspace_root().join("deny.toml"));
    let exceptions = lookup(&deny, &["licenses", "exceptions"])
        .and_then(toml::Value::as_array)
        .map_or(&[][..], Vec::as_slice);

    for exception in exceptions {
        let licenses = exception
            .get("allow")
            .and_then(toml::Value::as_array)
            .expect("an exception of deny.toml lists the licenses it allows");
        for license in licenses {
            let license = license.as_str().expect("a license is a string");
            assert!(
                accepted.contains(license),
                "deny.toml allows {license} to {exception}, about.toml does not accept it"
            );
        }
    }
}
