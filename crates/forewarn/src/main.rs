//! The `forewarn` command line: parses the arguments and wires the adapters to the domain (`specs/cli-check.md`,
//! `specs/cli-match.md`).

mod report;

use std::collections::HashSet;
use std::env;
use std::fmt::Display;
use std::fs::File;
use std::io::{self, ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, SystemTime};

use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use forewarn_cyclonedx::{ReadError, read_json};
use forewarn_domain::completeness::check;
use forewarn_domain::matching::{ComponentPackage, match_components};
use forewarn_domain::sbom::Sbom;
use forewarn_domain::vulnerability::Vulnerability;
use forewarn_osv::api::{Api, Package};
use forewarn_osv::fetch::{Archives, Refresh};
use forewarn_osv::{ReadError as OsvReadError, read_directory, read_record};

use report::Source;

/// Check a CycloneDX SBOM for the fields the EU Cyber Resilience Act expects, and match its components against known
/// vulnerabilities.
#[derive(Parser)]
#[command(version, arg_required_else_help = true)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print the spec version of an SBOM and the components missing a supplier, a license or a hash.
    Check(CheckArgs),
    /// Print the components of an SBOM affected by known OSV vulnerabilities, and those that could not be evaluated.
    Match(MatchArgs),
}

#[derive(Args)]
struct CheckArgs {
    /// The CycloneDX JSON SBOM to check, `-` for standard input (`./-` for a file named `-`).
    sbom: PathBuf,
    /// The format of the report.
    #[arg(long, value_enum, default_value_t = Format::Human)]
    format: Format,
    /// Exit with 0 when components are incomplete, so that a CI job reports the gaps without failing.
    #[arg(long)]
    allow_incomplete: bool,
}

#[derive(Args)]
struct MatchArgs {
    /// The CycloneDX JSON SBOM to match, `-` for standard input (`./-` for a file named `-`).
    sbom: PathBuf,
    /// An OSV record file, or a directory of them (an extracted OSV archive), read instead of fetching the OSV
    /// archives; repeat it for several.
    #[arg(long, conflicts_with_all = ["cache", "refresh", "osv_url"])]
    osv: Vec<PathBuf>,
    /// The cache of the OSV archives [default: `$XDG_CACHE_HOME/forewarn/osv`, else `$HOME/.cache/forewarn/osv`].
    #[arg(long)]
    cache: Option<PathBuf>,
    /// When to download an archive again: `offline`, `if-missing`, `always`, or when older than an age (`30m`, `12h`,
    /// `7d`) [default: 1d].
    #[arg(long, value_parser = parse_refresh)]
    refresh: Option<Refresh>,
    /// The URL the OSV archives are downloaded from (`<url>/<ecosystem>/all.zip`), a mirror for example
    /// [default: `https://osv-vulnerabilities.storage.googleapis.com`].
    #[arg(long)]
    osv_url: Option<String>,
    /// Query the OSV API instead of fetching the OSV archives: sends the OSV ecosystem, name and version of each
    /// component to the OSV API, out of the CI; the answer depends on the moment of the query.
    #[arg(long, conflicts_with_all = ["osv", "cache", "refresh", "osv_url"])]
    osv_api: bool,
    /// The URL of the OSV API queried with `--osv-api` [default: `https://api.osv.dev`].
    #[arg(long, requires = "osv_api")]
    osv_api_url: Option<String>,
    /// The format of the report.
    #[arg(long, value_enum, default_value_t = Format::Human)]
    format: Format,
    /// Exit with 0 when components are affected, so that a CI job reports them without failing.
    #[arg(long)]
    allow_affected: bool,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    /// Text for a person at a terminal.
    Human,
    /// One JSON document for a machine.
    Json,
}

/// The exit codes of CHK-7 and MCH-10; a usage error exits with 2, through `clap`.
const FOUND: u8 = 1;
const UNREADABLE: u8 = 3;
const UNWRITABLE: u8 = 4;
const NO_RECORDS: u8 = 5;

fn main() -> ExitCode {
    let outcome = match Cli::parse().command {
        Command::Check(args) => run_check(&args),
        Command::Match(args) => run_match(&args),
    };
    outcome.unwrap_or_else(ExitCode::from)
}

fn run_check(args: &CheckArgs) -> Result<ExitCode, u8> {
    let sbom = read_sbom(&args.sbom)?;
    let completeness = check(&sbom.components);
    write_report(&match args.format {
        Format::Human => report::human(&sbom, &completeness),
        Format::Json => report::json(&sbom, &completeness),
    })?;
    Ok(exit(!completeness.is_complete() && !args.allow_incomplete))
}

fn run_match(args: &MatchArgs) -> Result<ExitCode, u8> {
    // The arguments are checked before the SBOM is read (MCH-10).
    let archives = (args.osv.is_empty() && !args.osv_api).then(|| archives(args));
    let sbom = read_sbom(&args.sbom)?;
    let mut records = Records::default();
    let mut fetched = Vec::new();
    if let Some(archives) = archives {
        let snapshots = archives
            .fetch(&ecosystems(&sbom), SystemTime::now)
            .map_err(|error| no_records(&error))?;
        for snapshot in snapshots {
            let count = records.add(snapshot.vulnerabilities);
            fetched.push((snapshot.ecosystem, snapshot.freshness, count));
        }
    }
    let mut queried = None;
    if args.osv_api {
        let answer = api(args)
            .query(&packages(&sbom), SystemTime::now)
            .map_err(|error| no_records(&error))?;
        let count = records.add(answer.vulnerabilities);
        queried = Some((answer.freshness, count));
    }
    let mut local = Vec::new();
    for path in &args.osv {
        let read = read_osv(path).map_err(|error| no_records(&error))?;
        local.push((path, records.add(read)));
    }
    let matching = match_components(&sbom.components, &records.vulnerabilities);
    let sources: Vec<Source> = fetched
        .iter()
        .map(|(ecosystem, freshness, records)| Source::Archive {
            ecosystem,
            freshness,
            records: *records,
        })
        .chain(queried.iter().map(|(freshness, records)| Source::Api {
            freshness,
            records: *records,
        }))
        .chain(local.iter().map(|(path, records)| Source::Local {
            path,
            records: *records,
        }))
        .collect();
    write_report(&match args.format {
        Format::Human => report::matching_human(&sbom, &sources, &matching),
        Format::Json => report::matching_json(&sbom, &sources, &matching),
    })?;
    Ok(exit(!matching.matches().is_empty() && !args.allow_affected))
}

/// The archives of OSV the arguments name; exits with 2 when no cache directory can be found (MCH-12).
fn archives(args: &MatchArgs) -> Archives {
    let Some(cache) = args.cache.clone().or_else(default_cache) else {
        let mut cli = Cli::command();
        // Builds the names of the subcommands, so that the usage printed is that of `forewarn match`.
        cli.build();
        cli.find_subcommand_mut("match")
            .expect("the match subcommand")
            .error(
                clap::error::ErrorKind::MissingRequiredArgument,
                "no cache directory: give --cache, or set XDG_CACHE_HOME or HOME",
            )
            .exit();
    };
    let mut archives = Archives::new(cache, args.refresh.unwrap_or(DEFAULT_REFRESH));
    if let Some(url) = &args.osv_url {
        archives.base_url.clone_from(url);
    }
    archives
}

/// The OSV API the arguments name (MCH-27).
fn api(args: &MatchArgs) -> Api {
    let mut api = Api::default();
    if let Some(url) = &args.osv_api_url {
        api.base_url.clone_from(url);
    }
    api
}

/// The refresh policy without `--refresh`: an archive older than a day is downloaded again (MCH-11).
const DEFAULT_REFRESH: Refresh = Refresh::OlderThan(Duration::from_secs(24 * 60 * 60));

/// `$XDG_CACHE_HOME/forewarn/osv`, else `$HOME/.cache/forewarn/osv`; a relative `XDG_CACHE_HOME` is ignored, as the
/// XDG Base Directory specification says, and a variable set to nothing counts as unset.
fn default_cache() -> Option<PathBuf> {
    env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .filter(|cache| cache.is_absolute())
        .or_else(|| {
            env::var_os("HOME")
                .filter(|home| !home.is_empty())
                .map(|home| Path::new(&home).join(".cache"))
        })
        .map(|cache| cache.join("forewarn").join("osv"))
}

/// Reads a refresh policy: `offline`, `if-missing`, `always`, or an age, a positive whole number of `m`, `h` or `d`.
fn parse_refresh(text: &str) -> Result<Refresh, String> {
    match text {
        "offline" => return Ok(Refresh::Offline),
        "if-missing" => return Ok(Refresh::IfMissing),
        "always" => return Ok(Refresh::Always),
        _ => {}
    }
    let refused = || {
        format!(
            "`offline`, `if-missing`, `always`, or a positive age such as `30m`, `12h`, `7d`, not {text:?}"
        )
    };
    // The unit is the last character, which may not be ASCII (`1é`).
    let Some((count, unit)) = text
        .char_indices()
        .last()
        .map(|(at, unit)| (&text[..at], unit))
    else {
        return Err(refused());
    };
    let seconds = match unit {
        'm' => 60,
        'h' => 60 * 60,
        'd' => 24 * 60 * 60,
        _ => return Err(refused()),
    };
    if count.is_empty() || !count.bytes().all(|b| b.is_ascii_digit()) {
        return Err(refused());
    }
    match count
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(seconds))
    {
        Some(age) if age > 0 => Ok(Refresh::OlderThan(Duration::from_secs(age))),
        _ => Err(refused()),
    }
}

/// The OSV ecosystem of each component that maps to one, each once, in the order of its first component (MCH-5).
fn ecosystems(sbom: &Sbom) -> Vec<&'static str> {
    let mut ecosystems = Vec::new();
    for component in &sbom.components {
        if let Ok(package) = ComponentPackage::of(component)
            && !ecosystems.contains(&package.ecosystem)
        {
            ecosystems.push(package.ecosystem);
        }
    }
    ecosystems
}

/// The OSV ecosystem, name and version of each component that maps to an ecosystem, in the order of the SBOM (MCH-24).
fn packages(sbom: &Sbom) -> Vec<Package> {
    sbom.components
        .iter()
        .filter_map(|component| ComponentPackage::of(component).ok())
        .map(|package| Package {
            ecosystem: package.ecosystem.to_owned(),
            name: package.name,
            version: package.version,
        })
        .collect()
}

/// The vulnerabilities read, each id once (MCH-21).
#[derive(Default)]
struct Records {
    vulnerabilities: Vec<Vulnerability>,
    ids: HashSet<String>,
}

impl Records {
    /// Adds the vulnerabilities of a source whose id was not read before; returns how many the source held.
    fn add(&mut self, read: Vec<Vulnerability>) -> usize {
        let count = read.len();
        for vulnerability in read {
            if self.ids.insert(vulnerability.id.clone()) {
                self.vulnerabilities.push(vulnerability);
            }
        }
        count
    }
}

/// Prints why the OSV records cannot be read or fetched (MCH-14).
fn no_records(error: &dyn Display) -> u8 {
    eprintln!("error: {}", report::escaped(&error.to_string()));
    NO_RECORDS
}

/// Code 1 when the report found what a CI job fails on, else 0.
fn exit(found: bool) -> ExitCode {
    if found {
        ExitCode::from(FOUND)
    } else {
        ExitCode::SUCCESS
    }
}

/// Reads the SBOM, or prints why it cannot be read on standard error (CHK-8, MCH-14).
fn read_sbom(path: &Path) -> Result<Sbom, u8> {
    let sbom = if is_stdin(path) {
        read_json(io::stdin().lock())
    } else {
        File::open(path)
            .map_err(|e| ReadError::Io(e.to_string()))
            .and_then(read_json)
    };
    sbom.map_err(|error| {
        let error = format!("{}: {error}", input_name(path).display());
        eprintln!("error: {}", report::escaped(&error));
        UNREADABLE
    })
}

/// Reads an OSV record file, or each record of a directory.
fn read_osv(path: &Path) -> Result<Vec<Vulnerability>, OsvReadError> {
    if path.is_dir() {
        read_directory(path)
    } else {
        read_record(path).map(|vulnerability| vec![vulnerability])
    }
}

/// Prints the report on standard output, or why it cannot be (CHK-13, MCH-20).
fn write_report(text: &str) -> Result<(), u8> {
    match io::stdout().lock().write_all(text.as_bytes()) {
        // A closed pipe (`forewarn check sbom.json | head`) is not an error of the command.
        Err(error) if error.kind() != ErrorKind::BrokenPipe => {
            eprintln!("error: cannot write the report to standard output: {error}");
            Err(UNWRITABLE)
        }
        _ => Ok(()),
    }
}

fn is_stdin(path: &Path) -> bool {
    path.as_os_str() == "-"
}

fn input_name(path: &Path) -> &Path {
    if is_stdin(path) {
        Path::new("standard input")
    } else {
        path
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    use forewarn_osv::api::OSV_API;
    use forewarn_osv::fetch::OSV_ARCHIVES;

    use super::{Cli, Command, api, archives};

    // spec: MCH-27 (internal: a query of the OSV API needs the network)
    #[test]
    fn the_api_is_osv_dev_unless_a_url_is_given() {
        let base_url = |args: &[&str]| {
            let Command::Match(args) = Cli::parse_from(args).command else {
                panic!("a match command")
            };
            api(&args).base_url
        };
        assert_eq!(base_url(&["forewarn", "match", "--osv-api", "-"]), OSV_API);
        let mirror = [
            "forewarn",
            "match",
            "--osv-api",
            "--osv-api-url",
            "http://m",
            "-",
        ];
        assert_eq!(base_url(&mirror), "http://m");
    }

    // spec: MCH-13 (internal: a download from the OSV bucket needs the network)
    #[test]
    fn the_archives_come_from_the_osv_bucket_unless_a_url_is_given() {
        let base_url = |args: &[&str]| {
            let Command::Match(args) = Cli::parse_from(args).command else {
                panic!("a match command")
            };
            archives(&args).base_url
        };
        let default = ["forewarn", "match", "--cache", "c", "-"];
        assert_eq!(base_url(&default), OSV_ARCHIVES);
        let mirror = [
            "forewarn",
            "match",
            "--cache",
            "c",
            "--osv-url",
            "http://m",
            "-",
        ];
        assert_eq!(base_url(&mirror), "http://m");
    }
}
