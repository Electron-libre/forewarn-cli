# 0012. Align the early warning draft on the ENISA SRP glossary

- Status: accepted
- Date: 2026-11-13

## Context

CRA article 14 reports go through the ENISA Single Reporting Platform (SRP), operational since 11 September 2026. Its
FAQ (updated 15 October 2026, question 15) says no API is provided at the initial release: a person enters each
notification in the platform's web form. The fields of that form, and which of them each stage requires, are listed
in the CRA SRP Glossary, read at version 1.6 of 21 October 2026
(`https://www.enisa.europa.eu/topics/product-security/single-reporting-platform-srp/cra-srp-glossary2`). Secondary
sources quote older versions (1.1, 1.3) and other field counts; only the primary page was used.

For the 24-hour early warning of an actively exploited vulnerability (AEV), version 1.6 marks required: 1. Notification
type, 2. Title, 3. Summary, 4. Manufacturer name (filled by the platform from the registration, read-only),
5. Member States where the product is available, 6. Product Name, 7. Product Version; and mandatory: v26. Date and time
of awareness of the AEV. It marks optional, among others, 12. Component name, v19. CVE ID, v20. EUVD ID and
v22. Date the corrective or mitigating measure became available. It gives no contact field: the platform knows the
authorised representative who submits.

## Decision

- **The domain draft follows the required fields of glossary 1.6** for an AEV early warning
  (`specs/early-warning-draft.md`, EWD-9), plus the optional fields the tool fills exactly: the component, the CVE id,
  the EUVD id, the evidence of exploitation and the deadlines.
- **A required field the tool cannot fill exactly is listed as to complete**, never written as prose: the title, the
  summary and the Member States always; the manufacturer, the product name and version when the SBOM does not give
  them. The notification type is implied by the draft (always an AEV) and not listed.
- **One draft per CVE of the product**, listing each affected component: a notification is about a vulnerability of
  a product, and one draft per match would lead to two notifications of one CVE affecting two components.
- **The manufacturer is still taken from the SBOM**, although the platform fills its own: the vendor compares the two.
- **The domain names the fields, not the form**: the labels, numbers and order of the SRP form are written by the
  adapter (`write_the_early_warning_in_an_adapter`).

## Consequences

- A new version of the glossary is checked against the table of EWD-9: a field that becomes required at the early
  warning is added there, to complete unless the tool knows it exactly; the adapter follows for its labels.
- No contact field is drafted, unlike the issue's first approach: the glossary has none.
- Until an SRP API exists, the draft is read by a person, which the adapter's format serves.
