//! The `forewarn` command line: parses the arguments and wires the adapters to the domain (`specs/cli-check.md`,
//! `specs/cli-match.md`).

mod report;

use std::fs::File;
use std::io::{self, ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};
use forewarn_cyclonedx::{ReadError, read_json};
use forewarn_domain::completeness::check;
use forewarn_domain::matching::match_components;
use forewarn_domain::sbom::Sbom;
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
    /// An OSV record file, or a directory of them (an extracted OSV archive); repeat it for several.
    #[arg(long, required = true)]
    osv: Vec<PathBuf>,
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
    let sbom = read_sbom(&args.sbom)?;
    let mut vulnerabilities = Vec::new();
    for path in &args.osv {
        vulnerabilities.extend(read_osv(path).map_err(|error| {
            eprintln!("error: {error}");
            NO_RECORDS
        })?);
    }
    let matching = match_components(&sbom.components, &vulnerabilities);
    let sources: Vec<Source> = args.osv.iter().map(|path| Source::Local(path)).collect();
    write_report(&match args.format {
        Format::Human => report::matching_human(&sbom, &sources, &matching),
        Format::Json => report::matching_json(&sbom, &sources, &matching),
    })?;
    Ok(exit(!matching.matches().is_empty() && !args.allow_affected))
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
        eprintln!("error: {}: {error}", input_name(path).display());
        UNREADABLE
    })
}

/// Reads an OSV record file, or each record of a directory.
fn read_osv(
    path: &Path,
) -> Result<Vec<forewarn_domain::vulnerability::Vulnerability>, OsvReadError> {
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
