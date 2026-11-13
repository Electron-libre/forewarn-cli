---
id: EUV
status: accepted
adrs: [0004, 0005, 0007, 0008, 0009]
---

# EUVD exploited list reading

## Intent

Give the flagging of exploited vulnerabilities (`specs/exploited-flagging.md`) the vulnerabilities ENISA's European
Vulnerability Database (EUVD) knows to be exploited, read from a local file or paged from the EUVD API into a cache
under a refresh policy, so that a European vendor watches the list it is expected to watch, also in an air-gapped CI.

## Requirements

### Behaviour

- **EUV-1** (deterministic) Reading an EUVD exploited file must return an exploited list named `EUVD` holding, for each
  record of its `items` in the order of the file, an entry per CVE alias of the record (EUV-17), in the order of its
  aliases, each with the date of the record's `exploitedSince` (EUV-18), or with no date when it is absent, `null`, or
  not a date of EUV-18, so that a change of its format in EUVD drops the dates, not the list.
- **EUV-2** (deterministic) Reading must give no entry to a record none of whose aliases is a CVE id.
- **EUV-3** (deterministic) Fetching the list must return the list that reading the downloaded file returns (EUV-1),
  and the freshness of the download: the UTC time it started, the URL of EUV-7 it paged, and the `Last-Modified` header
  of its first page when the server sent one.
- **EUV-4** (deterministic) Fetching under the policy `offline` must send no request.
- **EUV-5** (deterministic) A fetch of the list that another fetch into the same cache is downloading must wait until
  that fetch is done with it, at most the time KEV-13 gives, as KEV-5 and KEV-13 say of the catalog.

### Contract

- **EUV-6** (deterministic) Fetching must download the list only as the refresh policy of the table of KEV-9 says, and
  otherwise read the copy of its cache.
- **EUV-21** (deterministic) withdrawn: replaced by EUV-22 to EUV-24.
- **EUV-22** (deterministic) A fetch of a cached list whose files differ from those its download stored must page it
  again, or fail under `offline`, as KEV-19 and KEV-20 say of the catalog.
- **EUV-23** (deterministic) A fetch of a cached list whose files are those its download stored, and that cannot be
  read, must fail with the error of reading it (EUV-15), without paging it again.
- **EUV-24** (deterministic) A cached list whose freshness names no files (stored by an earlier forewarn) must be
  paged again under `if-missing` or `older-than <age>`, and read as it is under `offline`.
- **EUV-7** (deterministic) A download must request its pages with a `GET` and no body of
  `<url>?exploited=true&size=100&page=<n>`, `<n>` from 0 up by one, `<url>` the one the caller gives,
  `https://euvdservices.enisa.europa.eu/api/search` unless it gives another, the `?` an `&` when `<url>` already holds
  a `?`; no other parameter is sent.
- **EUV-8** (deterministic) A download must stop paging after the first page whose `items` is empty, or once the
  records it collected, told apart by their `id`, number at least the `total` of its page 0.
- **EUV-9** (deterministic) A download must store in the cache one file of the shape `{"items": [...]}` holding each
  record collected once, the first time its `id` was seen, in the order of the pages, as the server sent it, that
  reading (EUV-1) accepts as a local file.
- **EUV-10** (deterministic) A download whose page gives a `total` other than that of its page 0, or that stops (EUV-8)
  with fewer records than that total, must start its paging again from page 0, three attempts in all, then fail with
  "list changed while paged" (EUV-15).
- **EUV-11** (deterministic) A download must fail with "page repeated" (EUV-15), without starting again, on a page whose
  `items` is not empty and holds only records an earlier page of the same attempt gave.
- **EUV-12** (deterministic) A fetch that reads the list from the cache must return the list and the freshness the
  download that stored it returned.
- **EUV-13** (deterministic) A download that fails, for any cause of EUV-15, must leave the copy the cache held before
  unchanged.
- **EUV-14** (deterministic) The fetched list must be kept in the directory `euvd-exploited` of the cache directory the
  caller gives.
- **EUV-15** (deterministic) A failed fetch must fail with the error of this table, its message quoting the offending
  value when there is one.

  | Cause | Error |
  |---|---|
  | the policy is `offline` and the cache holds no copy of the list | not cached |
  | another fetch still handles the list once the wait of EUV-5 is over | cache locked by another run, with the time waited |
  | the server cannot be reached, or answers a page with a status other than 200 | cannot download, with the URL of the page and the reason or the status |
  | a page is not JSON, or not an object whose `items` is a list of objects each with a string `id` and whose `total` is a non-negative integer | invalid page, with its number and the parser's reason |
  | a page repeats an earlier one (EUV-11) | page repeated, with its number |
  | the third attempt changed too (EUV-10) | list changed while paged, with the number of attempts |
  | the downloaded list cannot be read (EUV-16) | the error of EUV-16 |
  | the policy is `offline` and the files of the copy differ from those its download stored (EUV-22) | damaged cached copy, naming the first file that differs and whether it is missing, added or of another size |
  | the cache directory cannot be read or written | cannot use the cache, with the system's reason |

- **EUV-16** (deterministic) Reading a refused file must fail with the error of this table, the first cause that
  applies in table order, naming the file.

  | Cause | Error |
  |---|---|
  | the file cannot be read (an I/O error) | cannot read the input, with the system's reason |
  | the file is not JSON | not JSON |
  | `items` is absent or not a list, an element of it is not an object, its `id` is absent or not a string, or its `aliases` or `exploitedSince` is neither absent, `null` nor a string | invalid EUVD list, with the parser's reason |

- **EUV-17** (deterministic) The CVE aliases of a record must be the lines of its `aliases` (split on `\n`, a `\r`
  before it and the spaces around a line removed) that EXF-7 accepts as a CVE id, each once, ignoring ASCII case; the
  other lines (a `GHSA-` id, an empty line) are not aliases.
- **EUV-18** (deterministic) The date of `exploitedSince` must be the date it writes as `<Mon> <D>, <YYYY>, <h>:<mm>:<ss>
  <AM|PM>`, `<Mon>` among `Jan` to `Dec`, `<D>` one or two digits, a date of the Gregorian calendar, its time not read.
- **EUV-19** (deterministic) Reading must ignore the members of the file and of its records other than those of the
  table of EUV-16.
- **EUV-20** (deterministic) A download must fail with "cannot download" (EUV-15), naming the page it was at, once it
  has paged for the time the caller gives, 30 minutes unless it gives another, shorter than the wait of EUV-5.

## Scenarios

- **EUV-H1** (happy; EUV-1, EUV-17, EUV-18) Given a file whose `items` holds `EUVD-2026-62586` aliased
  `GHSA-9w8j-fg77-whw7\nCVE-2026-20320\n` exploited since `Nov 10, 2026, 12:00:00 AM` and `EUVD-2021-0001` aliased
  `CVE-2021-44228` exploited since `Dec 10, 2021, 12:00:00 AM`, when it is read, then the list `EUVD` holds
  `CVE-2026-20320` on 2026-11-10 and `CVE-2021-44228` on 2021-12-10, in that order.
- **EUV-H2** (happy; EUV-3, EUV-7, EUV-8, EUV-9, EUV-14) Given an empty cache and a server whose search gives a `total`
  of 150 over a page 0 of 100 records and a page 1 of 50, when the list is fetched under `if-missing`, then pages 0
  and 1 are requested with `exploited=true&size=100`, the cache directory `euvd-exploited` holds the 150 records in
  one file, and the fetch returns their entries with the time of the download, the URL and the `Last-Modified` of page 0.
- **EUV-H3** (happy; EUV-4, EUV-12) Given a cache filled by a fetch, when the list is fetched under `offline` with no
  server, then the fetch returns the list and the freshness of the first fetch, and no request is sent.
- (EUV-2) Given a record aliased only `GHSA-9w8j-fg77-whw7`, or with no `aliases`, when the file is read, then it gives
  no entry, and the records around it give theirs.
- (EUV-1, EUV-17) Given a record aliased `CVE-2026-1001\r\nCVE-2026-1002\ncve-2026-1001`, when the file is read, then it
  gives `CVE-2026-1001` then `CVE-2026-1002`, each once, with the record's date.
- (EUV-1) Given a record with no `exploitedSince`, or a `null` one, when the file is read, then its entries have no date.
- (EUV-5) Given a run downloading the list into a cache, when a second run fetches it under `if-missing`, then the
  second waits, then reads the copy the first stored, without a request.
- (EUV-6) Given a copy downloaded 2 hours ago, when it is fetched under `older-than 1h`, then the list is downloaded
  again; under `older-than 3h`, it is read from the cache.
- (EUV-22) Given a cached list file that was truncated, its freshness intact, when the list is fetched under
  `if-missing`, then it is paged again and its list returned; under `offline`, it fails with "damaged cached copy"
  and no request is sent.
- (EUV-23) Given a cached list file overwritten with as many bytes that are not JSON, when the list is fetched under
  `if-missing`, then it fails with "not JSON" and no request is sent.
- (EUV-24) Given a copy whose freshness holds no list of files, when the list is fetched under `if-missing`, then it is
  paged again; under `offline`, its list is returned.
- (EUV-8) Given a server whose `total` is 250 over pages of 100, 100 and 50 records, when the list is fetched, then pages
  0 to 2 are requested and page 3 is not.
- (EUV-8) Given a server whose `total` is 0 and whose page 0 is empty, when the list is fetched, then the list is empty.
- (EUV-10) Given a server whose page 1 repeats a record of page 0 then ends one record short of the `total` on the
  first attempt, and is stable on the second, when the list is fetched, then it is paged twice and the list holds every
  record once.
- (EUV-10) Given a server whose `total` is 150 on page 0 and 151 on page 1 at every attempt, when the list is fetched,
  then it fails with "list changed while paged" after 3 attempts.
- (EUV-11) Given a server that ignores `page` and answers page 0 to every request, when the list is fetched, then it
  fails with "page repeated" naming page 1, after two requests.
- (EUV-7) Given the URL `<mirror>/api/search?key=x`, when the list is fetched, then page 0 is requested at
  `<mirror>/api/search?key=x&exploited=true&size=100&page=0`.
- (EUV-20, EUV-13) Given a paging limit of 500 ms and a server that takes 3 s to answer page 1, when the list is
  fetched, then it fails with "cannot download" naming page 1 within the limit, and the former copy stays.
- (EUV-13, EUV-15) Given a copy in the cache and a server answering 503 to page 1, when the list is fetched under
  `always`, then it fails with "cannot download" naming the URL of page 1 and 503, and a later `offline` fetch returns
  the former copy.
- (EUV-15) Given a server whose page 0 is not JSON, or has no `total`, when the list is fetched, then it fails with
  "invalid page" naming page 0.
- (EUV-15) Given an empty cache, when the list is fetched under `offline`, then it fails with "not cached" and no
  request is sent.
- (EUV-16) Given a missing file, when it is read, then it fails with "cannot read the input" naming it.
- (EUV-16) Given a file without `items`, or a record without `id`, or whose `aliases` is a list, when it is read, then
  it fails with "invalid EUVD list".
- (EUV-1, EUV-18) Given a record whose `exploitedSince` is `2026-11-10`, `Feb 29, 2026, 12:00:00 AM` or `Nov 10 2026`,
  when the file is read, then its entries have no date, and the records around it keep theirs.
- (EUV-19) Given records holding `description`, `epss`, `enisaIdProduct` and an unknown member, and a file with a
  `total`, when it is read, then it is read as EUV-1 says.

## Non-goals

- Flagging the matches (`specs/exploited-flagging.md`), choosing the cache directory, printing the freshness or the
  flag in `forewarn match` (`specs/cli-match.md`, `specs/cli-match-exploited.md`).
- The endpoint `/api/exploitedvulnerabilities`: it gives only the latest few exploited records, not the list.
- The CSV dump `/api/dump/cve-euvd-mapping`: it maps EUVD ids to CVE ids but says nothing of exploitation.
- An entry for a record with no CVE alias (keyed by its `EUVD-` id): flagging compares CVE ids only (EXF-4).
- A page size other than 100: the API serves at most 100 records a page, whatever `size` asks.
- Waiting between pages: the API sends no rate limit, and a download pages about 18 times.
- Converting the time of `exploitedSince` to another time zone: its date is kept as EUVD writes it.
