---
name: document-openemr-fix
description: Write a new entry under docs/resolved/ recording an OpenEMR-side fix that CATS surfaced. Use when the user invokes /document-openemr-fix, says "document the OpenEMR fix", "log the upstream fix", or asks to record a resolved target bug. NOT for CATS-side bugs or workarounds.
---

# Document an OpenEMR fix

Write one markdown file under
[`docs/resolved/`](../../../docs/resolved/) recording an OpenEMR-side
bug that CATS surfaced and that has now been **fixed upstream in the
`openemr/` sibling repo**.

Read [`docs/resolved/README.md`](../../../docs/resolved/README.md)
first — it pins the required header shape, body sections, and what
counts as in-scope.

## Before writing

If `$ARGUMENTS` doesn't already name the issue (commit sha, trace
URL, or short description), ask the user for the minimum you need to
fill the header:

- Which openemr commit shipped the fix (sha + one-line summary).
- The component path and route/class that was affected.
- A pointer to what surfaced it on the CATS side (campaign id, trace
  URL, or a `docs/resolved/` cross-link).

Don't guess any of these. If the fix is not yet merged upstream, stop
— this folder tracks resolved issues only.

## File to write

Filename: `docs/resolved/YYYY-MM-DD-<short-slug>.md`, where `YYYY-MM-DD`
is the upstream merge date.

Follow the header + body sections exactly as
[`docs/resolved/README.md`](../../../docs/resolved/README.md)
specifies. The header is greppable metadata; the body is the retro
for a future reader.

## Hard rules

- **OpenEMR-side fixes only.** If the fix is in CATS (e.g. we
  changed `target_client.py` to send a different value, or routed
  around an upstream bug), it does **not** belong here. Tell the user
  and stop.
- **One file per fix.** No batching multiple fixes into a single
  entry.
- **Quote the upstream sha and link the commit.** If you can't, the
  entry isn't ready — ask the user first.
- **Cross-link.** If a related CATS workaround was already shipped,
  add the commit sha + a one-line note in the *Related* section so
  the workaround can be retired when this entry lands.
- **Don't add a CHANGELOG entry, README mention, or roadmap line.**
  This folder is the canonical record.

## After writing

Show the user the file path and a 3-line summary of the header. Don't
commit — let the user review first.
