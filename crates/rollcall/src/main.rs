//! The `rollcall` command line: parses the arguments and wires the adapters to the domain (`specs/cli-check.md`).

mod report;

use std::fs::File;
use std::io::{self, Write};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};
use rollcall_cyclonedx::{ReadError, read_json};
use rollcall_domain::completeness::check;
use rollcall_domain::sbom::Sbom;

// The help text is the package description (`about` with no value).
#[derive(Parser)]
#[command(version, about, arg_required_else_help = true)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print the spec version of an SBOM and the components missing a supplier, a license or a hash.
    Check(CheckArgs),
}

#[derive(Args)]
struct CheckArgs {
    /// The CycloneDX JSON SBOM to check, `-` for standard input.
    sbom: String,
    /// The format of the report.
    #[arg(long, value_enum, default_value_t = Format::Human)]
    format: Format,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    /// Text for a person at a terminal.
    Human,
}

/// The exit codes of CHK-7; a usage error exits with 2, through `clap`.
const INCOMPLETE: u8 = 1;
const UNREADABLE: u8 = 3;

fn main() -> ExitCode {
    let Command::Check(args) = Cli::parse().command;
    run_check(&args)
}

fn run_check(args: &CheckArgs) -> ExitCode {
    let sbom = match read_sbom(&args.sbom) {
        Ok(sbom) => sbom,
        Err(error) => {
            eprintln!("error: {}: {error}", input_name(&args.sbom));
            return ExitCode::from(UNREADABLE);
        }
    };
    let completeness = check(&sbom.components);
    let text = match args.format {
        Format::Human => report::human(&sbom, &completeness),
    };
    // A closed standard output (`rollcall check sbom.json | head`) is not an error of the check.
    let _ = io::stdout().lock().write_all(text.as_bytes());
    if completeness.is_complete() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(INCOMPLETE)
    }
}

fn read_sbom(path: &str) -> Result<Sbom, ReadError> {
    if path == "-" {
        read_json(io::stdin().lock())
    } else {
        let file = File::open(path).map_err(|e| ReadError::Io(e.to_string()))?;
        read_json(file)
    }
}

fn input_name(path: &str) -> &str {
    if path == "-" { "standard input" } else { path }
}
