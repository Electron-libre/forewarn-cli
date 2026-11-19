//! The CI templates of `examples/ci/` a vendor copies: each `forewarn` command they run, and each option they give it,
//! exists in the binary, so renaming an option breaks this build instead of the vendors' pipelines; and the archive
//! they install is one the release workflow builds, of the workspace version that `just set-version` moves at each
//! release.
//! The same holds for the daily watch of the project's own releases, `.github/workflows/watch.yml`: the options it gives
//! `forewarn match` exist, and the files it downloads are ones the release workflow publishes.

mod common;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use common::run;

/// The directory of the templates, each a `.yml` file.
const TEMPLATES: &str = "examples/ci";

/// The commands a template must run: the whole of a release check.
const COMMANDS: [&str; 3] = ["check", "match", "upload"];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the crate lives two levels below the workspace root")
        .to_path_buf()
}

/// The templates of `examples/ci/`, relative to the workspace root, sorted: each is checked, none forgotten.
fn templates() -> Vec<String> {
    let dir = workspace_root().join(TEMPLATES);
    let mut found: Vec<String> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|entry| entry.expect("an entry of the directory").file_name())
        .filter_map(|name| name.into_string().ok())
        .filter(|name| {
            Path::new(name)
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("yml"))
        })
        .map(|name| format!("{TEMPLATES}/{name}"))
        .collect();
    found.sort();
    assert!(
        found.len() >= 2,
        "{TEMPLATES} holds no GitHub and GitLab templates: {found:?}"
    );
    found
}

fn read(relative: &str) -> String {
    let path = workspace_root().join(relative);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The shell lines of a template, comments and step names left out and the lines continued by a `\` joined.
fn shell_lines(template: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut pending = String::new();
    for line in template.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with("name:") || line.starts_with("- name:") {
            continue;
        }
        if let Some(continued) = line.strip_suffix('\\') {
            pending.push_str(continued);
            pending.push(' ');
        } else {
            pending.push_str(line);
            lines.push(std::mem::take(&mut pending));
        }
    }
    lines
}

/// Each `forewarn <command>` of a template with the options it gives, long or short, `--name=value` read as `--name`
/// (`-` alone, standard input, is no option).
fn invocations(template: &str) -> Vec<(String, Vec<String>)> {
    let mut found = Vec::new();
    for line in shell_lines(template) {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        for (i, window) in tokens.windows(2).enumerate() {
            if window[0] != "forewarn" || !COMMANDS.contains(&window[1]) {
                continue;
            }
            let options = tokens[i + 2..]
                .iter()
                .take_while(|token| !matches!(**token, "|" | "&&" | "||" | ";" | ">" | "2>"))
                .filter(|token| token.starts_with('-') && token.len() > 1)
                .map(|token| token.split('=').next().unwrap_or(token).to_owned())
                .collect();
            found.push((window[1].to_owned(), options));
        }
    }
    found
}

/// Whether the help of a command describes `option`: a line of its option column (`  -h, --help`, `      --name`)
/// naming it, alone or followed by its value; a description, indented further, never counts.
fn describes(help: &str, option: &str) -> bool {
    help.lines()
        .filter_map(|line| {
            line.strip_prefix("  -")
                .map(|rest| format!("-{rest}"))
                .or_else(|| {
                    line.strip_prefix("      --")
                        .map(|rest| format!("--{rest}"))
                })
        })
        .any(|entry| {
            entry
                .split(", ")
                .any(|name| name == option || name.starts_with(&format!("{option} ")))
        })
}

#[test]
fn each_template_runs_each_command_with_options_the_binary_has() {
    for template in templates() {
        let found = invocations(&read(&template));

        let commands: BTreeSet<&str> = found.iter().map(|(command, _)| command.as_str()).collect();
        assert_eq!(
            commands,
            BTreeSet::from(COMMANDS),
            "{template}: commands run: {found:?}"
        );
        for (command, options) in &found {
            let help = run(&[command, "--help"], None);
            assert_eq!(help.code, 0, "forewarn {command} --help: {}", help.stderr);
            for option in options {
                assert!(
                    describes(&help.stdout, option),
                    "{template}: forewarn {command} has no option {option}"
                );
            }
        }
    }
}

/// The archive suffix a template derives from the runner's architecture: `uname -m` names the first part of the
/// target triple.
const UNAME_TARGET: &str = "$(uname -m)-unknown-linux-musl";

/// The architectures `uname -m` names on the runners a template derives its archive for.
const UNAME_ARCHITECTURES: [&str; 2] = ["x86_64", "aarch64"];

/// The targets a template can install: the value of its line `TARGET: <triple>`, or each architecture of
/// `UNAME_ARCHITECTURES` when it derives the triple from `uname -m`.
fn template_targets(template: &str) -> BTreeSet<String> {
    let mut targets: BTreeSet<String> = template
        .lines()
        .filter_map(|line| line.trim().strip_prefix("TARGET:"))
        .map(|target| target.trim().to_owned())
        .collect();
    if template.contains(UNAME_TARGET) {
        targets.extend(
            UNAME_ARCHITECTURES
                .iter()
                .map(|architecture| UNAME_TARGET.replace("$(uname -m)", architecture)),
        );
    }
    targets
}

/// The `target` of each entry of the build matrix of the release workflow: the lines `- target: <triple>`.
fn released_targets() -> BTreeSet<String> {
    read(".github/workflows/release.yml")
        .lines()
        .filter_map(|line| line.trim().strip_prefix("- target:"))
        .map(|target| target.trim().to_owned())
        .collect()
}

#[test]
fn each_template_installs_an_archive_the_release_builds() {
    let released = released_targets();
    for template in templates() {
        let targets = template_targets(&read(&template));

        assert!(
            !targets.is_empty(),
            "{template} names no target it installs"
        );
        for target in targets {
            assert!(
                released.contains(&target),
                "{template} installs {target}, which no release builds"
            );
        }
    }
}

/// The versions a template pins, the values of its lines `FOREWARN_VERSION: ...` (indented with spaces only), the
/// lines `just set-version` rewrites.
fn pinned_versions(template: &str) -> Vec<String> {
    template
        .lines()
        .filter_map(|line| {
            line.trim_start_matches(' ')
                .strip_prefix("FOREWARN_VERSION: ")
        })
        .map(str::to_owned)
        .collect()
}

#[test]
fn each_template_pins_the_workspace_version() {
    for template in templates() {
        assert!(
            Path::new(&template).extension() == Some("yml".as_ref()),
            "{template}: `just set-version` rewrites the templates named `*.yml` only"
        );
        assert_eq!(
            pinned_versions(&read(&template)),
            [env!("CARGO_PKG_VERSION")],
            "{template} must pin the workspace version on one line `FOREWARN_VERSION: X.Y.Z`, with nothing after \
             it: run `just set-version <version>`"
        );
    }
}

/// The workflow that matches the latest release of forewarn each day.
const WATCH: &str = ".github/workflows/watch.yml";

#[test]
fn the_watch_workflow_matches_with_options_the_binary_has() {
    let found = invocations(&read(WATCH));

    let commands: BTreeSet<&str> = found.iter().map(|(command, _)| command.as_str()).collect();
    assert_eq!(
        commands,
        BTreeSet::from(["match"]),
        "{WATCH}: commands run: {found:?}"
    );
    let help = run(&["match", "--help"], None);
    assert_eq!(help.code, 0, "forewarn match --help: {}", help.stderr);
    for (_, options) in &found {
        for option in options {
            assert!(
                describes(&help.stdout, option),
                "{WATCH}: forewarn match has no option {option}"
            );
        }
    }
}

#[test]
fn the_watch_workflow_downloads_files_the_release_publishes() {
    let watch = read(WATCH);
    let release = read(".github/workflows/release.yml");

    let archives: Vec<&str> = watch
        .lines()
        .filter_map(|line| line.trim().strip_prefix("ARCHIVE: forewarn-"))
        .collect();
    assert_eq!(
        archives.len(),
        1,
        "{WATCH} must name the archive it installs on one line `ARCHIVE: forewarn-<target>`"
    );
    assert!(
        released_targets().contains(archives[0]),
        "{WATCH} installs {}, which no release builds",
        archives[0]
    );
    for (downloaded, published) in [
        (
            "--pattern \"$ARCHIVE.tar.gz\"",
            "ARCHIVE: forewarn-${{ matrix.target }}",
        ),
        (
            "--pattern 'forewarn-*.cdx.json'",
            "--override-filename \"forewarn-$target.cdx\"",
        ),
        ("--pattern 'forewarn-*.cdx.json'", "cp notices/sbom/*.cdx.json dist/"),
        ("--pattern SHA256SUMS", "> SHA256SUMS"),
    ] {
        assert!(
            watch.contains(downloaded),
            "{WATCH} does not download {downloaded}"
        );
        assert!(
            release.contains(published),
            "release.yml no longer publishes what {downloaded} downloads"
        );
    }
}
