# Injection ground-truth fixtures

`ground_truth.jsonl` — one JSON object per line, shape:

```
{"attack": {...}, "response": "...", "expected_verdict": "pass|fail|partial"}
```

CI runs the Judge against every triple and enforces a per-category accuracy
threshold (≥95% for injection). Hand-labeled; populated post-scaffold.
