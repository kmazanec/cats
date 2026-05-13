# Resolved OpenEMR issues

> **Scope:** One markdown file per bug or security defect that CATS
> surfaced **in the OpenEMR target** and that has been **fixed in
> OpenEMR**. Cross-repo PRs / commits land in the sibling
> `openemr/` repository; this folder is CATS's running log of what
> we've reported and what's been resolved upstream.
>
> **Not in scope:**
> - CATS-side bugs (those go in commit messages + tests, not here).
> - CATS-side workarounds for OpenEMR bugs that haven't been fixed
>   upstream — those stay open. Add them here once the upstream fix
>   lands.
> - Issues we identified but haven't reported.
>
> **Filename convention:** `YYYY-MM-DD-<short-slug>.md`, dated to the
> day the upstream fix merged.
>
> **Required header block** (so future readers can grep without
> reading the body):
>
> ```markdown
> > **Target:** <component path inside openemr/>
> > **Surface:** <route / module / class that was vulnerable>
> > **Severity:** <Low | Medium | High | Critical> (+ one-line why)
> > **Status:** Fixed in openemr commit <sha>
> > **Found:** <date> — <campaign id or trace url that surfaced it>
> > **Reported:** <date> (issue/PR link if applicable)
> > **Fixed:** <date> — openemr commit <sha>
> > **Class:** <attack family or defect class — e.g. "JWT validation",
> >           "Prompt injection — supervisor routing", "DoS — graph
> >           recursion">
> ```
>
> **Body sections** (in order):
> 1. *What broke* — observable behavior, one paragraph.
> 2. *Root cause (OpenEMR side)* — point at the file + lines.
> 3. *Resolution* — what changed in openemr and why.
> 4. *Why CATS didn't catch this earlier / Why it surfaced now* —
>    one-paragraph retro on the detection pipeline.
> 5. *Related* — cross-links to other resolved entries or open
>    workarounds in CATS.

This folder is currently empty. Entries land here as OpenEMR fixes
ship for issues we've surfaced.
