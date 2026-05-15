# VLN-YYYY-NNN — <one-line title; ≤ 80 chars>

> Vulnerability report produced from a confirmed CATS finding. Format
> follows the Week-3 brief's prescribed shape: ID + severity, description
> + clinical impact, minimal reproduction, observed vs expected,
> remediation, current status + fix-validation.

| Field | Value |
|---|---|
| **Report ID** | VLN-YYYY-NNN |
| **Severity** | `info` \| `low` \| `medium` \| `high` \| `critical` — <one-line justification: what makes this severity floor correct> |
| **Exploitability** | `confirmed` \| `plausible` \| `theoretical` — <evidence: live Judge ruling + reproducibility note> |
| **OWASP LLM** | `LLM01` (Prompt Injection) \| `LLM02` (Sensitive Information Disclosure) \| `LLM05` (Improper Output Handling) \| `LLM06` (Excessive Agency) \| `LLM07` (System Prompt Leakage) \| `LLM09` (Misinformation) \| `LLM10` (Unbounded Consumption) — pick the closest 2025 ID. Use `—` only when no LLM-side weakness applies. |
| **MITRE ATLAS** | `AML.T<id>` — closest ATLAS technique. Use `—` when the bug is not LLM-mediated. |
| **Regression** | `none` \| `regressed from VLN-YYYY-NNN` — link the prior report when the deploy-time sweep re-promoted the same signature. |
| **Category** | <CATS category name> — <free-form behavioral class> |
| **Target component** | <repo + file path, e.g. `agent/src/graph/nodes/supervisor.ts`> |
| **Discovered** | <ISO date> — CATS campaign / run link |
| **Reported** | <ISO date> — channel (in-thread, GH issue, etc.) |
| **Status** | **Open** \| **Resolved** — <one-line> |
| **Fix-validation** | <how was the fix validated; regression-sweep status; test names> |

## Description + clinical impact

<Plain-English description of what the attack does and what the model
or component did wrong. Then a "Clinical impact" paragraph naming the
worst-case clinical consequence in concrete terms. Then "Exploitability"
notes if the structured field above isn't enough.>

## Minimal reproduction

<Endpoint, auth context, exact attacker payload in a fenced block,
exact observed response excerpt in another fenced block. Anyone with
the target running locally should be able to follow these steps.>

## Observed vs expected

<Two sub-sections or a bullet list. The expected behavior cites the
relevant baseline doc (e.g. `reports/tool_abuse/baselines.md`) or the
upstream contract.>

## Recommended remediation

<2–4 concrete, ordered-by-leverage suggestions. No generic security
boilerplate — every suggestion must reference *this* finding.>

## Status + fix-validation

<Where the upstream fix landed (commit SHA, PR), what regression tests
were added, and whether the CATS regression sweep has ratified the fix.>
