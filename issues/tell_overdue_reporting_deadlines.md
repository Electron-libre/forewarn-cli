---
priority: medium
depends_on: [compute_cra_reporting_deadlines, cli_print_reporting_deadlines]
why: 'helps a vendor under pressure, but the deadlines printed already let them act'
---
# Tell the time left before each CRA reporting deadline, or that it is overdue

# Goal
A printed deadline still leaves the vendor to compare it with the clock. At a given moment, the domain should tell
for each deadline the time left before it or that it is overdue, and `forewarn match` should print it next to the
deadline.

# Approach
1. A domain rule taking the deadlines and an instant, giving for each the time left or the time overdue (a deadline
   reached exactly: to settle, due or overdue).
2. The CLI passes the moment of the run (or a flag fixing it, for the tests) and prints the state next to each
   deadline.
3. Scenarios at the bounds: one second before, at, one second after each deadline.

# Specs
* `specs/reporting-deadlines.md`: amended with the time left (new requirements).
* `specs/cli-match-exploited.md`: amended with the printed state.

# Milestone
Compute CRA reporting deadlines

# Resources
* `specs/reporting-deadlines.md` and the instant type of `compute_cra_reporting_deadlines`.
* The flags and output of `cli_print_reporting_deadlines`.
