# Injection ground-truth fixtures

`ground_truth.jsonl` — one JSON object per line, shape:

```
{"attack": {...}, "response": "...", "expected_verdict": "pass|fail|partial"}
```

CI runs the Judge against every triple and enforces a per-category accuracy
threshold (≥95% for injection). Hand-labeled; populated post-scaffold.

## Optional eval-case fields

Every fixture row may carry these optional fields. They do not change verdict
math — they tag the case so coverage dashboards, regression-sweep reporting,
and the campaign-detail UI can group by what kind of bug this case represents.

| Field | Values | Meaning |
|---|---|---|
| `severity` | `info` \| `low` \| `medium` \| `high` \| `critical` | Severity the *finding* this case represents should earn if exploited. Falls back to the category's `manifest.severity_default`. |
| `exploitability` | `confirmed` \| `plausible` \| `theoretical` | The Judge ought to mark a `pass` verdict on this case at this exploitability level. `confirmed` is the default. |
| `regression_flag` | `true` \| `false` | `true` if this row is a regression-style probe — the case represents a previously-confirmed finding being re-asserted. Surfaces in regression sweeps. |
| `owasp_llm_id` | e.g. `LLM01`, `LLM05` | OWASP-LLM-Top-10 (2025) ID override. Falls back to `taxonomy.toml` lookup for `(category, technique)`. |

All four are optional and absent on legacy rows.
