---
id: MVX
status: accepted
adrs: [0014]
---

# The VEX verdicts of `forewarn match`

## Intent

Let a vendor record, in CycloneDX VEX inside the SBOM or in files of their own, that a match does not affect their
product, and see `forewarn match` report it apart, with the verdict, rather than fail the CI, mark it actively
exploited or draft its early warning.

## Requirements

### Behaviour

- **MVX-1** (deterministic) `forewarn match <sbom>` must apply the verdicts of the SBOM (VEX-1) to the matches
  (VEX-3) and print each match set aside apart from the affected ones, with its component, its id, its aliases, the
  state, the justification and the detail of its verdict, and the evidence of the lists naming it (MXL-1).
- **MVX-2** (deterministic) `forewarn match --vex <path> <sbom>` must also apply the verdicts of the VEX document of
  that file (VEX-2), the option given once per document, after those of the SBOM in the order of the options.
- **MVX-3** (deterministic) When the SBOM holds a verdict or `--vex` is given, the human report of `forewarn match`
  must print how many matches were set aside, and the sources of verdicts it read, the SBOM and the path of each
  `--vex` file, each with its number of verdicts; otherwise it prints none of them.
- **MVX-4** (deterministic) A match set aside must count neither as an affected component nor as an actively
  exploited match for the exit code (MCH-10), nor in the count of MXL-1, nor get deadlines (MXL-14).
- **MVX-5** (deterministic) `forewarn match --drafts <dir> <sbom>` must write no draft for a CVE whose matches are all
  set aside.
- **MVX-10** (deterministic) A draft of a CVE some of whose matches are set aside must name only the components of
  its matches left (EWD-1).
- **MVX-6** (deterministic) `forewarn match <sbom>` must print each verdict that names no match of the run, with its
  ids and its targets, so that a mistyped `bom-ref` or id is seen.

### Contract

- **MVX-7** (deterministic) A `--vex` file that cannot be read must exit with 3 (MCH-10) and print one line on
  standard error naming the file and the error of SBR-7 (VEX-12).
- **MVX-8** (deterministic) The JSON report must hold the members of this table, beside those of MCH-16.

  | Member | Value |
  |---|---|
  | `vex` | an array of objects `{"kind": "sbom", "verdictCount"}` then `{"kind": "file", "path", "verdictCount"}` in the order of MVX-2 |
  | `setAsideCount` | the number of matches set aside |
  | `setAside` | an array, in the order of VEX-10, of objects with the members of an entry of `affected` (MCH-16) but `awareSince` and `deadlines`, and `verdict`, an object `{"state", "justification", "detail", "source"}`, `justification` and `detail` a string or `null`, `source` `"sbom"` or the path of the `--vex` file |
  | `unusedVerdicts` | an array of objects `{"ids", "targets", "source"}` of MVX-6, in the order of the verdicts |

- **MVX-9** (deterministic) The human report must print the justification and the detail of a verdict, and the
  targets of an unused one, as MCH-18 says of the values of the SBOM.

## Scenarios

- **MVX-H1** (happy; MVX-1, MVX-3, MVX-4, MVX-5) Given an SBOM with `log4j-core` 2.14.1 whose `vulnerabilities` say
  `CVE-2021-44228` `not_affected`, `code_not_reachable`, OSV records naming it and a KEV catalog naming the CVE, when
  the vendor runs `forewarn match --osv records/ --kev kev.json --drafts drafts/ sbom.json`, then the report lists
  `log4j-core` set aside with the verdict and the KEV evidence, 0 actively exploited, no draft is written and the
  command exits with 0.
- **MVX-H2** (happy; MVX-2, MVX-8) Given an SBOM without `vulnerabilities` and a file `vex.json` saying
  `false_positive` for one of its two matches, when the vendor runs
  `forewarn match --format json --vex vex.json ... sbom.json`, then `setAside` holds that match with `source`
  `vex.json`, `affected` the other, and the command exits with 1.
- (MVX-4, MVX-10) Given an SBOM whose two matches share `CVE-2021-44228`, actively exploited, and a verdict setting aside the
  first, when it is matched with `--drafts`, then the draft of `CVE-2021-44228` names the second component only and
  the command exits with 6.
- (MVX-2) Given `--vex a.json --vex b.json`, where `a.json` says `not_affected` and `b.json` `exploitable` for the same
  match, when it is matched, then the match stays affected (VEX-9).
- (MVX-7) Given `--vex` naming a file that is not JSON, when the SBOM is matched, then standard error names the file
  and "not JSON".

## Non-goals

- `--vex -` (standard input): the SBOM may be read from it (MCH-7).
- Applying verdicts in `forewarn check`: completeness does not depend on them.
- Writing a VEX document from the report.
