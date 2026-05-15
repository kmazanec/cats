# Vulnerability reports — OpenEMR target

> Brief-format vulnerability reports CATS has produced for issues found
> in the OpenEMR Clinical Co-Pilot. Each report follows the Week-3
> brief's prescribed six-section shape: ID + severity, description +
> clinical impact, minimal reproduction, observed vs expected,
> remediation, and current status + fix-validation.

These are the reports a senior security engineer who was not present
when the exploit was found could reproduce, validate, and fix from. The
companion narratives under [`../../docs/resolved/`](../../docs/resolved/)
are the CATS-side retros on each finding and link back to these
reports.

## Reports

| ID | Severity | Title | Status |
|---|---|---|---|
| [VLN-2026-001](./VLN-2026-001-supervisor-chart-enriched-fanout-dos.md) | Medium | Supervisor chart-enriched fanout exhausts agent graph recursion (DoS) | Resolved — openemr `2ff40efba` |
| [VLN-2026-002](./VLN-2026-002-extract-php-jwt-issuer-mismatch.md) | High | `extract.php` mints JWTs with the wrong issuer claim | Resolved — openemr `7b2b6c80d` |
| [VLN-2026-003](./VLN-2026-003-supervisor-chart-area-over-read.md) | Medium | Supervisor coerced past `default_briefing` baseline via adversarial chat phrasing | Resolved (case 1) — openemr `d0eda9986`; case 2 follow_up-tagged variant tracked as a known gap |

Additional reports are added as the Documentation agent promotes
confirmed Judge verdicts; see `/findings` on
<https://cats.biograph.dev> for the live list.

## Naming convention

`VLN-YYYY-NNN-<short-slug>.md`, monotonically numbered within a year.
Slug is kebab-case and short — the title carries the full description.

## How these reports are produced

In production, the Documentation agent (`src/cats/agents/documentation/`)
writes a draft when the Judge returns a `pass` verdict and the
Documentation worker dequeues the `DocumentationRequested` envelope.
Critical-severity drafts pause for human approval before they're
promoted (R9 trust gate). The two reports here were written from
existing `docs/resolved/` notes — they're the same content rendered in
the brief's prescribed format for reviewer convenience.
