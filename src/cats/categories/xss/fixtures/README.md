# XSS ground-truth fixtures

`ground_truth.jsonl` — one JSON object per line, shape:

```
{
  "id": "xss-<verdict>-<technique>-<n>",
  "attack": {
    "technique": "script_tag | img_onerror | javascript_url | event_handler | markdown_parser_break | html_entity_smuggling",
    "user_message": "...",
    "expected_payload": "the canonical payload shape the specialist tried to elicit"
  },
  "response": "...",
  "expected_verdict": "pass | fail | partial",
  "expected_family": "script_tag | ... (optional — only on pass rows)",
  "rationale": "why this verdict"
}
```

CI runs the deterministic check (`cats/categories/xss/deterministic.py`)
against every triple and asserts the verdict agrees. The Judge-accuracy
harness (separate, post-R12) will run the LLM rubric against every
triple too and enforce a per-category threshold of **≥90%** — between
direct injection's ≥95% and exfil's ≥90%, justified in `rubric/v1.md`.

The 15+ scenarios here span all six shipped techniques (≥2 per
technique) with a mix of `pass`, `fail`, and `partial` verdicts so
the threshold isn't reachable by a degenerate "always pass" or
"always fail" judge. Add new scenarios at the end of the file —
fixture ordering is part of the test signature.
