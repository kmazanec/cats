# VLN-2026-002 — `extract.php` mints JWTs with the wrong issuer claim (pipeline-trigger broken)

> Vulnerability report produced from a confirmed CATS-adjacent finding.
> Format follows the Week-3 brief's prescribed shape: ID + severity,
> description + clinical impact, minimal reproduction, observed vs
> expected, remediation, current status + fix-validation.

| Field | Value |
|---|---|
| **Report ID** | VLN-2026-002 |
| **Severity** | `high` — every panel-side document upload silently failed; pipeline-trigger unreachable. No PHI exposure, no auth bypass — the agent's verifier stayed strict and refused the malformed token; the defect was on the mint side. |
| **Exploitability** | `theoretical` — the bug is a defense-side mis-mint that the verifier rejected. The structural weakness (two code paths composing the same issuer string) is real, but no actor used it to gain unauthorized access; the only observed impact is availability. |
| **OWASP LLM** | — |
| **MITRE ATLAS** | — |
| **Regression** | none |
| **Category** | Tool misuse — authorization-token forgery via configuration drift (not cryptographic) |
| **Target component** | OpenEMR Clinical Co-Pilot — `interface/modules/custom_modules/oe-module-clinical-copilot/public/extract.php` |
| **Discovered** | 2026-05-13 — surfaced by direct inspection of the agent container log after an OpenEMR-maintainer report. CATS campaign [`10f44930-413c-4ba0-805e-81e3195af83a`](https://cats.biograph.dev/campaigns/10f44930-413c-4ba0-805e-81e3195af83a) was running concurrently and exercised `extract.php` 30 times across 20 runs without flagging the issue — a CATS-side detection gap, documented in §"Why CATS missed this" below. |
| **Reported** | 2026-05-13 (in-thread maintainer report; no external issue/PR) |
| **Status** | **Resolved** — fixed upstream in openemr commit `7b2b6c80d` on 2026-05-13 |
| **Fix-validation** | ✅ Structural-regression test `IssuerResolutionConsistencyTest.php` added; data-providers over every browser-inbound mint entry point (`agent.php`, `extract.php`) and asserts both presence of the shared helper and absence of inline issuer composition. Manual smoke against `/agent.php?action=echo` confirms both entry points now compose the byte-identical string `https://localhost:9300/oauth2/default`. |

## Description + clinical impact

The Clinical Co-Pilot's panel-upload-to-extraction pipeline broke
silently for every clinician. A user uploading a chart document through
the Co-Pilot panel triggered `POST /extract.php`, which minted a JWT
bearer for the upstream agent. The mint composed the issuer claim
directly from `site_addr_oath + webroot + '/oauth2/' + siteId` — the
OpenEMR-self URL on the docker network. The agent container was pinned
(via `AGENT_JWT_ISSUER` env) to the browser-facing URL, which differs
in scheme and port. `jose`'s `jwtVerify` compares `iss` byte-for-byte,
so verification failed with `ERR_JWT_CLAIM_VALIDATION_FAILED`. The
proxy had already flushed SSE response headers before issuing the
upstream POST, so the agent's 401 came back to the browser as a 200
text/event-stream response with a body of `{"error":"unauthorized"}`
— unparseable by `EventSource`, no extraction ever started.

**Clinical impact.** Every panel-side document upload silently failed
to enter the extraction pipeline. A clinician attaching a chart
document via the Co-Pilot panel saw the upload appear (the PHP-side
write succeeded) but the document's content never reached the agent,
so subsequent briefings referencing that document had no extracted
content to draw on. Failure was silent on the user surface — no error
toast, no upload-failed indicator — making this a clinically-relevant
correctness bug: the assistant would answer with missing context but
appear to be working normally.

The defect did not bypass authentication or expose PHI. The agent's
verifier correctly rejected the malformed token; the failure was on
the mint side. Severity is **High** because of clinical-correctness
impact and the silent failure mode, not because of exploitability.

The sibling `agent.php` route was unaffected — it had already migrated
to a shared issuer-resolver in an earlier commit. The class of defect
is "feature broken," not "feature exploitable."

## Minimal reproduction sequence

1. Bring up the OpenEMR dev stack with the agent container's
   `AGENT_JWT_ISSUER` env pointing at the **external** URL the browser
   uses:

   ```yaml
   # docker-compose.yml (agent service)
   environment:
     AGENT_JWT_ISSUER: https://localhost:9300/oauth2/default
   ```

2. Leave OpenEMR's own `site_addr_oath` global at its docker-network
   self-URL (this is the default for the dev stack):

   ```
   site_addr_oath = http://localhost:8300
   ```

3. Sign in to OpenEMR. Open the Clinical Co-Pilot panel for any
   patient.

4. Attach any PDF or DOCX file via the panel's upload control. The
   browser issues `POST .../extract.php`.

5. Observe in the browser dev-tools network tab: response status
   `200 OK`, response content-type `text/event-stream`, response body
   `{"error":"unauthorized"}`. The panel's `EventSource` cannot parse
   this as an SSE frame and stays idle.

6. Inspect the agent container log:

   ```bash
   docker logs cats-target-agent | grep -i 'jwt\|iss'
   ```

   You will see `JWT verification failed: unexpected "iss" claim
   value` and `err: ERR_JWT_CLAIM_VALIDATION_FAILED`.

7. For comparison, the sibling `agent.php` route works correctly with
   the same stack — same proxy, same agent, same JWT minter — which is
   how the bug was localized to `extract.php`.

## Observed vs. expected behavior

| | Observed (pre-fix) | Expected |
|---|---|---|
| `POST .../extract.php` wire response | HTTP 200, `Content-Type: text/event-stream`, body `{"error":"unauthorized"}` | HTTP 200 SSE stream with `data: {...}` extraction-progress frames, terminating in `data: {"ok":true,...}` |
| JWT `iss` claim minted by `extract.php` | `http://localhost:8300/oauth2/default` (OpenEMR self-URL on docker network) | `https://localhost:9300/oauth2/default` (browser-facing URL, matching `AGENT_JWT_ISSUER`) |
| Issuer composition path | Inline composition from globals | Shared `AgentEndpointBootstrap::resolveIssuer($siteId)` helper, identical to `agent.php` |
| Visible failure on the user surface | None — panel upload appears to succeed, no error toast, no spinner stall | Either success or a visible failure with retry option |

## Recommended remediation

The fix the OpenEMR team adopted (commit `7b2b6c80d`) is two changes:

1. **Route `extract.php` through the shared issuer resolver.** Replace
   the inline composition with the helper that `agent.php` already
   uses. The helper honors the `OE_AGENT_JWT_ISSUER` override and falls
   back to the direct composition only when unset — same behavior as
   the sibling route, parameterized identically:

   ```php
   use OpenEMR\Modules\ClinicalCopilot\Bootstrap\AgentEndpointBootstrap;
   // …
   $issuer = AgentEndpointBootstrap::resolveIssuer($siteId);
   ```

2. **Add a structural-regression test that locks the contract.** New
   PHPUnit test at
   `tests/Tests/Isolated/Modules/ClinicalCopilot/Auth/IssuerResolutionConsistencyTest.php`
   data-provides over every browser-inbound mint entry point and
   asserts:
   - **positive**: the call to `AgentEndpointBootstrap::resolveIssuer()`
     is present;
   - **negative**: the inline `$siteAddr . $webroot . '/oauth2/'`
     composition is absent.

   The next sibling mint route that gets added will hit a red CI
   before it hits this same bug.

The agent verifier itself should **not** be relaxed. Iss validation
stays strict — no permissive mode, no regex fallback. The bug was the
mint side composing the wrong string; the verify side did its job.

## Fix-validation

Validation was performed in two layers:

1. **Smoke against the patched stack.** A `/agent.php?action=echo` hit
   (which shares the same mint path) returned `200 text/event-stream`
   with a parseable `data: {"ok":true,...}` frame. The agent log
   recorded:

   ```
   {"level":20,"component":"auth","fhirUser":"…","jti":"…","msg":"authenticated agent request"}
   ```

   A runtime computation inside the OpenEMR container confirmed both
   entry points now compose the byte-identical string
   `https://localhost:9300/oauth2/default`.

2. **Per-MR regression gate.** `IssuerResolutionConsistencyTest`
   enforces the structural invariant on every OpenEMR MR. The next
   sibling mint route that ships without the helper fails CI before
   merge.

## Why CATS missed this (detection-gap retro)

CATS exercised `extract.php` 30 times across 20 runs during the same
campaign that was running when this bug was live and produced **zero**
findings on it. The detection gap is in CATS's response-interpretation
layer, not its attack surface:

- **Status-code-driven detection.** The Output Filter and the Judge
  treat HTTP 200 as success. The proxy's pre-stream-error path leaks
  `application/json` body content under a `text/event-stream`
  content-type — semantically a 401, but the wire status was 200
  because SSE headers had already flushed. Nothing in the pipeline
  cross-checks content-type against body shape.

- **No agent-log correlation.** A finding here would have required
  CATS to read the target agent's container log, notice
  `ERR_JWT_CLAIM_VALIDATION_FAILED`, and tie it back to the
  execution. The agent-side observability exists; the Orchestrator
  just doesn't consume it.

- **No per-route smoke prelude.** A campaign could hit each mint entry
  point with a known-good envelope before running the Red Team and
  abort if any returned an auth-error body — this exact bug would have
  tripped that gate on probe #1.

These three follow-ups are tracked as platform-side improvements; they
do not affect the OpenEMR-side fix-validation above.

## Cross-references

- Originating CATS-internal note: [`docs/resolved/2026-05-13-extract-php-jwt-issuer-mismatch.md`](../docs/resolved/2026-05-13-extract-php-jwt-issuer-mismatch.md)
- Related vulnerability discovered same day, separate fix: [`VLN-2026-001`](./VLN-2026-001-supervisor-chart-enriched-fanout-dos.md)
- Upstream fix commit: openemr `7b2b6c80d` — *"fix(copilot): route extract.php through resolveIssuer() like agent.php"*
- Helper introduced in: openemr `744a888b6` — original `AgentEndpointBootstrap::resolveIssuer()` migration
