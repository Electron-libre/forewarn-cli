//! The CI templates of `examples/ci/` a vendor copies: each `forewarn` command they run, and each option they give it,
//! exists in the binary, so renaming an option breaks this build instead of the vendors' pipelines; and the archive
//! they install is one the release workflow builds.

mod common;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use common::run;

const GITHUB_ACTIONS: &str = "examples/ci/github-actions.yml";

/// The commands a template must run: the whole of a release check.
const COMMANDS: [&str; 3] = ["check", "match", "upload"];

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
fn the_github_actions_template_runs_each_command_with_options_the_binary_has() {
    let found = invocations(&read(GITHUB_ACTIONS));

    let commands: BTreeSet<&str> = found.iter().map(|(command, _)| command.as_str()).collect();
    assert_eq!(
        commands,
        BTreeSet::from(COMMANDS),
        "commands run: {found:?}"
    );
    for (command, options) in &found {
        let help = run(&[command, "--help"], None);
        assert_eq!(help.code, 0, "forewarn {command} --help: {}", help.stderr);
        for option in options {
            assert!(
                describes(&help.stdout, option),
                "{GITHUB_ACTIONS}: forewarn {command} has no option {option}"
            );
        }
    }
}

/// The value of the variable `TARGET` a template sets: the line `TARGET: <triple>`.
fn template_target(template: &str) -> String {
    template
        .lines()
        .find_map(|line| line.trim().strip_prefix("TARGET:"))
        .expect("the template sets the TARGET it installs")
        .trim()
        .to_owned()
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
fn the_github_actions_template_installs_an_archive_the_release_builds() {
    let target = template_target(&read(GITHUB_ACTIONS));

    assert!(
        released_targets().contains(&target),
        "{GITHUB_ACTIONS} installs {target}, which no release builds"
    );
}
