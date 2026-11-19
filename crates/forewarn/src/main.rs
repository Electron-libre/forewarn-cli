//! The `forewarn` command line: parses the arguments and wires the adapters to the domain (`specs/cli-check.md`,
//! `specs/cli-match.md`, `specs/cli-match-exploited.md`, `specs/cli-upload.md`).

mod args;
mod drafts;
mod early_warning;
mod error_line;
mod escape;
mod report;
mod upload;
mod vex;

use std::collections::HashSet;
use std::env;
use std::fs::File;
use std::io::{self, ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, SystemTime};

use clap::{CommandFactory, Parser};
use forewarn_cyclonedx::{ReadError, read_json, read_vex_json};
use forewarn_domain::completeness::check;
use forewarn_domain::deadlines::{DeadlinePastRange, reporting_deadlines};
use forewarn_domain::early_warning::draft_early_warnings;
use forewarn_domain::exploited::{ExploitedList, FlaggedReport, flag_exploited};
use forewarn_domain::matching::{ComponentPackage, match_components};
use forewarn_domain::sbom::Sbom;
use forewarn_domain::vex::{Verdict, apply_verdicts};
use forewarn_domain::vulnerability::Vulnerability;
use forewarn_exploited::{euvd, kev};
use forewarn_osv::api::{Api, Package};
use forewarn_osv::fetch::{Archives, Refresh};
use forewarn_osv::{ReadError as OsvReadError, read_directory, read_record};

use args::{CheckArgs, Cli, Command, Format, GivenMoment, MatchArgs, moment};
use error_line::ErrorLine;
use report::{Awareness, ExploitedSource, Origin, Source};

/// The exit codes of CHK-7 and MCH-10; a usage error exits with 2, through `clap`.
const FOUND: u8 = 1;
const UNREADABLE: u8 = 3;
const UNWRITABLE: u8 = 4;
const NO_RECORDS: u8 = 5;
const EXPLOITED: u8 = 6;
const DRAFT_UNWRITABLE: u8 = 7;

fn main() -> ExitCode {
    let outcome = match Cli::parse().command {
        Command::Check(args) => run_check(&args),
        Command::Match(args) => run_match(&args),
        Command::Upload(args) => upload::run(&args),
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
    let awareness = awareness(args);
    let fetches_archives = args.osv.is_empty() && !args.osv_api;
    let fetches_kev = args.kev.is_none() && !args.no_kev;
    let fetches_euvd = args.euvd.is_none() && !args.no_euvd;
    let fetches_any = fetches_archives || fetches_kev || fetches_euvd;
    if !fetches_any && (args.cache.is_some() || args.refresh.is_some()) {
        usage_error(
            clap::error::ErrorKind::ArgumentConflict,
            "--cache and --refresh apply to what is fetched: neither the OSV archives (--osv, --osv-api), the \
             CISA KEV catalog (--kev, --no-kev) nor the EUVD list (--euvd, --no-euvd) are",
        );
    }
    let cache =
        fetches_any.then(|| cache_directory(args, fetches_archives, fetches_kev, fetches_euvd));
    let refresh = args.refresh.unwrap_or(DEFAULT_REFRESH);
    let archives = cache
        .clone()
        .filter(|_| fetches_archives)
        .map(|cache| archives(args, cache, refresh));
    let feed = cache
        .clone()
        .filter(|_| fetches_kev)
        .map(|cache| kev_feed(args, cache, refresh));
    let euvd_feed = cache
        .filter(|_| fetches_euvd)
        .map(|cache| euvd_feed(args, cache, refresh));
    let sbom = read_sbom(&args.sbom)?;
    let vex_files = read_vex_files(&args.vex)?;
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
    // The exploited lists come after the OSV records, so that a local error is reported before a download.
    let (catalog, euvd_list) = exploited_lists(args, feed, euvd_feed)?;
    // CISA KEV, then EUVD: the order of the evidence (EXF-5, MXL-6).
    let exploited: Vec<ExploitedSource> = catalog
        .iter()
        .map(KevCatalog::source)
        .chain(euvd_list.iter().map(EuvdList::source))
        .collect();
    let verdicts = vex::Verdicts::new(&sbom, &vex_files);
    let matching = matched(&sbom, &records.vulnerabilities, &exploited, &verdicts);
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
    // The drafts before the report, so that a draft not written leaves standard output empty (MXL-33).
    let drafts = args
        .drafts
        .as_ref()
        .map(|directory| write_drafts(directory, &sbom, &awareness, &matching))
        .transpose()?;
    let report = report::MatchReport {
        sbom: &sbom,
        sources: &sources,
        exploited: &exploited,
        awareness: &awareness,
        matching: &matching,
        drafts: drafts.as_ref(),
        verdicts: &verdicts,
    };
    write_report(&match args.format {
        Format::Human => report::matching_human(&report),
        Format::Json => report::matching_json(&report),
    })?;
    if matching.exploited_count() > 0 {
        return Ok(ExitCode::from(EXPLOITED));
    }
    Ok(exit(!matching.matches().is_empty() && !args.allow_affected))
}

/// Matches the components of `sbom`, flags the matches the exploited lists name, then sets aside those the verdicts
/// do, after the flagging so that a match set aside keeps its evidence (MVX-1, ADR 0014).
fn matched(
    sbom: &Sbom,
    vulnerabilities: &[Vulnerability],
    exploited: &[ExploitedSource],
    verdicts: &vex::Verdicts,
) -> FlaggedReport {
    apply_verdicts(
        flag_exploited(
            match_components(&sbom.components, vulnerabilities),
            exploited.iter().map(|source| source.list),
        ),
        verdicts.all(),
        &sbom.components,
    )
}

/// Writes the draft early warning of each actively exploited CVE into `directory` (MXL-27) and lists the stale ones
/// (MXL-36), or prints why a draft cannot be written or the directory listed and returns the code 7 (MXL-33, MXL-40).
fn write_drafts(
    directory: &Path,
    sbom: &Sbom,
    awareness: &Awareness,
    matching: &FlaggedReport,
) -> Result<drafts::Drafts, u8> {
    let drafted = draft_early_warnings(
        matching,
        sbom.product.as_ref(),
        awareness.since,
        awareness.measure_available,
    )
    .expect("the deadlines of the moments given were checked before the SBOM was read");
    let product = sbom.product.as_ref().map(|product| product.name.as_str());
    drafts::write(directory, product, &drafted).map_err(|error| {
        eprintln!("error: {}", error.line());
        DRAFT_UNWRITABLE
    })
}

/// The moments the reporting deadlines of the run are computed from, those deadlines and the moment they are checked
/// at (MXL-14 to MXL-17, MXL-23); exits with 2, naming the option and the value given, when a deadline falls past the
/// year 9999 (MXL-20).
fn awareness(args: &MatchArgs) -> Awareness {
    // The clock is read once, for the moment of awareness and the moment of the check alike (MXL-23).
    let run = (args.aware_since.is_none() || args.now.is_none()).then(|| {
        report::offset_date_time(SystemTime::now())
            .and_then(moment)
            .unwrap_or_else(|| {
                let missing = [
                    (args.aware_since.is_none(), "--aware-since"),
                    (args.now.is_none(), "--now"),
                ]
                .into_iter()
                .filter_map(|(missing, option)| missing.then_some(option))
                .collect::<Vec<_>>()
                .join(" and ");
                usage_error(
                    clap::error::ErrorKind::InvalidValue,
                    &format!(
                        "the clock of the system gives no moment of the years 1 to 9999: give {missing}"
                    ),
                )
            })
    });
    let given_or_run = |given: Option<&GivenMoment>| {
        given
            .map(|given| given.moment)
            .or(run)
            .expect("the clock is read when a moment is not given")
    };
    let since = given_or_run(args.aware_since.as_ref());
    // The moment of awareness first, so that the error of a final report names the measure (MXL-20).
    reporting_deadlines(since, None)
        .unwrap_or_else(|error| past_range("--aware-since", args.aware_since.as_ref(), error));
    let measure_available = args.measure_available.as_ref().map(|given| given.moment);
    let deadlines = reporting_deadlines(since, measure_available).unwrap_or_else(|error| {
        past_range(
            "--measure-available",
            args.measure_available.as_ref(),
            error,
        )
    });
    Awareness {
        since,
        given: args.aware_since.is_some(),
        measure_available,
        deadlines,
        checked_at: given_or_run(args.now.as_ref()),
        checked_given: args.now.is_some(),
    }
}

/// Exits with 2 naming the option and the value given whose deadline falls past the year 9999 (MXL-20).
fn past_range(option: &str, given: Option<&GivenMoment>, error: DeadlinePastRange) -> ! {
    let text = given.map_or_else(|| error.0.to_string(), |given| given.text.clone());
    usage_error(
        clap::error::ErrorKind::InvalidValue,
        &format!("invalid value '{text}' for '{option}': {error}"),
    )
}
/// The CISA KEV catalog and the EUVD list of a run, the files given read before a list is fetched (MXL-2, MXL-3,
/// MXL-6, MXL-7).
fn exploited_lists(
    args: &MatchArgs,
    kev_feed: Option<kev::Feed>,
    euvd_feed: Option<euvd::Feed>,
) -> Result<(Option<KevCatalog<'_>>, Option<EuvdList<'_>>), u8> {
    // A list is either given or fetched, never both (MCH-10).
    let local_kev = args
        .kev
        .as_ref()
        .map(|path| kev::read_file(path).map(|catalog| KevCatalog::Local(catalog, path)))
        .transpose()
        .map_err(|error| no_records(&error))?;
    let local_euvd = args
        .euvd
        .as_ref()
        .map(|path| euvd::read_file(path).map(|list| EuvdList::Local(list, path)))
        .transpose()
        .map_err(|error| no_records(&error))?;
    let fetched_kev = kev_feed
        .map(|feed| feed.fetch(SystemTime::now).map(KevCatalog::Fetched))
        .transpose()
        .map_err(|error| no_records(&error))?;
    let fetched_euvd = euvd_feed
        .map(|feed| feed.fetch(SystemTime::now).map(EuvdList::Fetched))
        .transpose()
        .map_err(|error| no_records(&error))?;
    Ok((local_kev.or(fetched_kev), local_euvd.or(fetched_euvd)))
}

/// The CISA KEV catalog of a run: a file given with `--kev`, or fetched into the cache (MXL-2, MXL-3).
enum KevCatalog<'a> {
    Local(kev::Catalog, &'a Path),
    Fetched(kev::FetchedCatalog),
}

impl KevCatalog<'_> {
    fn source(&self) -> ExploitedSource<'_> {
        let (catalog, origin) = match self {
            Self::Local(catalog, path) => (catalog, Origin::Local(path)),
            Self::Fetched(fetched) => (&fetched.catalog, Origin::Fetched(&fetched.freshness)),
        };
        ExploitedSource {
            list: &catalog.list,
            release: Some((&catalog.version, catalog.released)),
            origin,
        }
    }
}

/// The exploited list of EUVD of a run: a file given with `--euvd`, or paged into the cache (MXL-6, MXL-7).
enum EuvdList<'a> {
    Local(ExploitedList, &'a Path),
    Fetched(euvd::FetchedList),
}

impl EuvdList<'_> {
    fn source(&self) -> ExploitedSource<'_> {
        let (list, origin) = match self {
            Self::Local(list, path) => (list, Origin::Local(path)),
            Self::Fetched(fetched) => (&fetched.list, Origin::Fetched(&fetched.freshness)),
        };
        ExploitedSource {
            list,
            release: None,
            origin,
        }
    }
}

/// Prints a usage error of `forewarn match` and exits with 2, as `clap` does for the errors it finds.
fn usage_error(kind: clap::error::ErrorKind, message: &str) -> ! {
    subcommand_usage_error("match", kind, message)
}

/// Prints a usage error of `forewarn <subcommand>` and exits with 2, as `clap` does for the errors it finds.
fn subcommand_usage_error(subcommand: &str, kind: clap::error::ErrorKind, message: &str) -> ! {
    let mut cli = Cli::command();
    // Builds the names of the subcommands, so that the usage printed is that of the subcommand.
    cli.build();
    cli.find_subcommand_mut(subcommand)
        .expect("a subcommand of the command line")
        .error(kind, message)
        .exit()
}

/// The cache directory of MCH-12; exits with 2 when none can be found, naming the options that fetch no exploited list
/// when only those lists need it.
fn cache_directory(
    args: &MatchArgs,
    fetches_archives: bool,
    fetches_kev: bool,
    fetches_euvd: bool,
) -> PathBuf {
    args.cache
        .clone()
        .or_else(default_cache)
        .unwrap_or_else(|| {
            let mut message =
                "no cache directory: give --cache, or set XDG_CACHE_HOME or HOME".to_owned();
            if !fetches_archives {
                message.push_str(match (fetches_kev, fetches_euvd) {
                    (true, true) => {
                        ", or give --kev <file> or --no-kev, and --euvd <file> or --no-euvd, to fetch no \
                         exploited list"
                    }
                    (true, false) => ", or give --kev <file> or --no-kev to fetch no CISA KEV catalog",
                    (false, true) => ", or give --euvd <file> or --no-euvd to fetch no EUVD list",
                    (false, false) => "",
                });
            }
            usage_error(clap::error::ErrorKind::MissingRequiredArgument, &message)
        })
}

/// The archives of OSV the arguments name (MCH-13).
fn archives(args: &MatchArgs, cache: PathBuf, refresh: Refresh) -> Archives {
    let mut archives = Archives::new(cache, refresh);
    if let Some(url) = &args.osv_url {
        archives.base_url.clone_from(url);
    }
    archives
}

/// The EUVD list the arguments name, kept in the entry `euvd-exploited` of the cache (MXL-12, MXL-13).
fn euvd_feed(args: &MatchArgs, cache: PathBuf, refresh: Refresh) -> euvd::Feed {
    let mut feed = euvd::Feed::new(cache, refresh);
    if let Some(url) = &args.euvd_url {
        feed.url.clone_from(url);
    }
    feed
}

/// The CISA KEV catalog the arguments name, kept in the entry `cisa-kev` of the cache (MXL-10, MXL-11).
fn kev_feed(args: &MatchArgs, cache: PathBuf, refresh: Refresh) -> kev::Feed {
    let mut feed = kev::Feed::new(cache, refresh);
    if let Some(url) = &args.kev_url {
        feed.url.clone_from(url);
    }
    feed
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

/// The OSV ecosystem, name and version of each component that maps to an ecosystem, in the order of the SBOM; a Go
/// version without its leading `v`, as OSV writes the versions of Go modules (MCH-24).
fn packages(sbom: &Sbom) -> Vec<Package> {
    sbom.components
        .iter()
        .filter_map(|component| ComponentPackage::of(component).ok())
        .map(|package| Package {
            ecosystem: package.ecosystem.to_owned(),
            name: package.name,
            version: match (package.ecosystem, package.version.strip_prefix('v')) {
                ("Go", Some(bare)) => bare.to_owned(),
                _ => package.version,
            },
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

/// Prints why the OSV records or the KEV catalog cannot be read or fetched (MCH-14).
fn no_records(error: &dyn ErrorLine) -> u8 {
    eprintln!("error: {}", error.line());
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
    sbom.map_err(|error| unreadable(input_name(path), &error))
}

/// Prints why the CycloneDX document of `path` cannot be read and returns the code 3 (MCH-14, MVX-7).
fn unreadable(path: &Path, error: &ReadError) -> u8 {
    eprintln!("error: {}", error_line::path_and_cause(path, error));
    UNREADABLE
}

/// Reads the verdicts of each `--vex` file, in order; prints why one cannot be read and returns the code 3 (MVX-7).
fn read_vex_files(paths: &[PathBuf]) -> Result<Vec<(&Path, Vec<Verdict>)>, u8> {
    paths
        .iter()
        .map(|path| {
            File::open(path)
                .map_err(|e| ReadError::Io(e.to_string()))
                .and_then(read_vex_json)
                .map(|verdicts| (path.as_path(), verdicts))
                .map_err(|error| unreadable(path, &error))
        })
        .collect()
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

    use forewarn_exploited::euvd::EUVD_SEARCH;
    use forewarn_exploited::kev::KEV_CATALOG;

    use super::{Cli, Command, DEFAULT_REFRESH, api, archives, euvd_feed, kev_feed};

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
            archives(&args, "c".into(), DEFAULT_REFRESH).base_url
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

    // spec: MXL-10 (internal: a download from cisa.gov needs the network)
    #[test]
    fn the_kev_catalog_comes_from_cisa_unless_a_url_is_given() {
        let url = |args: &[&str]| {
            let Command::Match(args) = Cli::parse_from(args).command else {
                panic!("a match command")
            };
            kev_feed(&args, "c".into(), DEFAULT_REFRESH).url
        };
        assert_eq!(url(&["forewarn", "match", "-"]), KEV_CATALOG);
        let mirror = ["forewarn", "match", "--kev-url", "http://m/kev.json", "-"];
        assert_eq!(url(&mirror), "http://m/kev.json");
    }

    // spec: MXL-12 (internal: paging the EUVD search needs the network)
    #[test]
    fn the_euvd_list_comes_from_enisa_unless_a_url_is_given() {
        let url = |args: &[&str]| {
            let Command::Match(args) = Cli::parse_from(args).command else {
                panic!("a match command")
            };
            euvd_feed(&args, "c".into(), DEFAULT_REFRESH).url
        };
        assert_eq!(url(&["forewarn", "match", "-"]), EUVD_SEARCH);
        let mirror = [
            "forewarn",
            "match",
            "--euvd-url",
            "http://m/api/search",
            "-",
        ];
        assert_eq!(url(&mirror), "http://m/api/search");
    }
}
