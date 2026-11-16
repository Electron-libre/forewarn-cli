---
id: CHK
status: accepted
adrs: [0001]
---

# The `forewarn check` command

## Intent

Let a vendor, at a terminal or in a CI job, check a CycloneDX SBOM in one command: see its spec version, flagged when
it is below the BSI TR-03183-2 minimum, and the components missing the fields the CRA expects, with an exit code a CI
job can act on.

## Requirements

### Behaviour

- **CHK-1** (deterministic) `forewarn check <sbom>` must print the spec version of the SBOM and, when it is below the
  BSI TR-03183-2 minimum (1.6), a flag saying so.
- **CHK-2** (deterministic) `forewarn check <sbom>` must print each incomplete component of the completeness check
  (`specs/sbom-completeness.md`) with its name, its version and package URL when it has them, and its missing fields.
- **CHK-3** (deterministic) `forewarn check <sbom>` must print how many components were checked and how many are
  incomplete, or that the SBOM is complete.
- **CHK-4** (deterministic) `forewarn check -` must read the SBOM from standard input, so that the output of an SBOM
  generator can be piped into it.
- **CHK-5** (deterministic) `forewarn check --format json <sbom>` must print the same result as one JSON document, for
  a machine to read.
- **CHK-6** (deterministic) `forewarn check --allow-incomplete <sbom>` must exit with the code of a complete SBOM when
  the SBOM is incomplete, the report printed unchanged, so that a CI job can report gaps without failing.

### Contract

- **CHK-7** (deterministic) The command must exit with the code of this table, the first row that applies.

  | Situation | Exit code |
  |---|---|
  | the arguments are invalid (unknown option, unknown format, no SBOM given) | 2 |
  | the SBOM cannot be read (any error of SBR-7) | 3 |
  | the report cannot be written to standard output, a closed pipe aside (CHK-13) | 4 |
  | the SBOM is incomplete, without `--allow-incomplete` | 1 |
  | the SBOM is complete, or incomplete with `--allow-incomplete` | 0 |

- **CHK-8** (deterministic) An SBOM that cannot be read must print nothing on standard output and one line on standard
  error naming the path (`standard input` for `-`) and the error of SBR-7.
- **CHK-9** (deterministic) The report, in either format, must be printed on standard output and nothing else on
  standard error.
- **CHK-10** (deterministic) The JSON report must be one object with the members of this table.

  | Member | Value |
  |---|---|
  | `specVersion` | the spec version, a string (`"1.6"`) |
  | `belowBsiMinimum` | `true` when the spec version is below 1.6, else `false` |
  | `componentCount` | the number of components checked, nested ones included |
  | `complete` | `true` when no component is incomplete, else `false` |
  | `incomplete` | an array, in SBOM order, of objects `name`, `version` (string or `null`), `purl` (string or `null`), `missing` (an array of `"supplier"`, `"license"`, `"hash"`, in that order) |

- **CHK-11** (deterministic) `--format` must accept `human`, the default, and `json`.
- **CHK-12** (deterministic) `forewarn` with no subcommand must print its usage, naming `check`, and exit with code 2.
- **CHK-13** (deterministic) A report that cannot be written to standard output must print one line on standard error
  naming the cause, unless standard output is a closed pipe (`forewarn check sbom.json | head`), which is not an
  error.
- **CHK-14** (deterministic) The human report must print each control character of a component's name, version or
  package URL escaped (`\n`, `\u{1b}`), each character that hides or reorders text (EWD-16) as its Unicode escape
  (`\u{202e}`) and each backslash as `\\`, so that an SBOM cannot forge report lines or terminal sequences, nor
  reorder or hide the text a person reads, and each escape reads back to one value.

## Scenarios

- **CHK-H1** (happy; CHK-1, CHK-2, CHK-3, CHK-7) Given an SBOM a vendor generated with `syft` in CycloneDX 1.6, whose
  components lack a supplier and a license, when they run `forewarn check sbom.json`, then they see `CycloneDX 1.6`
  with no flag, each component with its missing fields, the count of incomplete components, and the command exits
  with 1.
- **CHK-H2** (happy; CHK-4, CHK-5, CHK-10, CHK-6) Given a CI job that pipes an SBOM generator into
  `forewarn check --format json --allow-incomplete -`, when the SBOM is incomplete, then the job reads a JSON report
  listing the incomplete components and the command exits with 0.
- **CHK-H3** (happy; CHK-1, CHK-3, CHK-7) Given a CycloneDX 1.5 SBOM whose every component has a supplier, a license
  and a hash, when the vendor runs `forewarn check`, then they see `CycloneDX 1.5` flagged as below the BSI TR-03183-2
  minimum, that the SBOM is complete, and the command exits with 0.
- (CHK-7) Given an SBOM below the BSI minimum, when it is checked, then the flag alone does not change the exit code.
- (CHK-7, CHK-8) Given a path that does not exist, when it is checked, then standard error names the path and "cannot
  read the input", and the command exits with 3.
- (CHK-7, CHK-8) Given a CycloneDX 1.2 file piped into `forewarn check -`, when it is checked, then standard error
  names `standard input` and "unsupported spec version", and the command exits with 3.
- (CHK-7) Given a path that is not valid UTF-8, when it is checked, then it is read like any other path, not
  refused as an invalid argument.
- (CHK-7, CHK-13) Given standard output redirected to a full device, when a report is printed, then standard error
  names the cause and the command exits with 4.
- (CHK-14) Given a component named `evil` followed by a newline and an escape sequence, when the human report prints
  it, then it stays on one line with `\n` and `\u{1b}` written out.
- (CHK-14) Given a component whose version holds U+202E (right-to-left override) and U+200B (zero-width space), when
  the human report prints it, then `\u{202e}` and `\u{200b}` are written out.
- (CHK-14) Given a component whose version holds the tag character U+E0041 and the Hangul filler U+3164, when the
  human report prints it, then `\u{e0041}` and `\u{3164}` are written out.
- (CHK-14) Given a component whose name holds the text `\u{202e}`, a backslash followed by `u{202e}`, when the human
  report prints it, then it reads `\\u{202e}`, unlike a name holding a real U+202E.
- (CHK-4) Given a file named `-`, when the user means that file, then they write `./-`: `-` alone is standard input.
- (CHK-7, CHK-11) Given `--format xml`, when the command runs, then it exits with 2 before reading the SBOM.
- (CHK-3, CHK-10) Given a valid SBOM with no component, when it is checked, then it is complete with 0 components and
  the command exits with 0.
- (CHK-2, CHK-10) Given an incomplete component with no version and no package URL, when it is checked, then the
  human report shows its name alone and the JSON report gives `null` for both.

## Non-goals

- The exact layout of the human report beyond what CHK-1 to CHK-3 state: it may change without notice; scripts read
  the JSON report.
- Escaping the formatting characters in the JSON report: it escapes what JSON requires, and a program reads it.
- A versioned JSON schema: the members of CHK-10 are the contract until a later issue versions it.
- Checking several SBOMs in one run, or a directory.
- Colours, or a `--quiet` option.
- Failing on an SBOM below the BSI minimum: it is flagged, not refused (`specs/sbom-reading.md`).
- Matching vulnerabilities: `forewarn match` (`specs/cli-match.md`); drafting reports or uploading: later subcommands.
