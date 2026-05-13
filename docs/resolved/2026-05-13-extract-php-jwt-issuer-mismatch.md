> **Target:** `interface/modules/custom_modules/oe-module-clinical-copilot/public/extract.php`
> **Surface:** Browser → proxy → agent pipeline-trigger route (`POST /extract.php`). The `agent.php` sibling route was unaffected because it already used the shared issuer resolver.
> **Severity:** High availability bug — every pipeline-trigger request (panel upload → extract) was unreachable: the proxy stamped SSE response headers, minted a JWT with the wrong `iss`, the agent rejected it with `ERR_JWT_CLAIM_VALIDATION_FAILED`, and the proxy piped the 401 body through. Net effect: panel uploads never reached the agent's extraction pipeline at all. No auth bypass, no PHI exposure — the failure mode was strictly "feature broken," not "feature exploitable." Not Critical because the agent's verifier correctly refused the malformed token; the bug was on the mint side, and the agent stayed closed.
> **Status:** Fixed in openemr commit `7b2b6c80d`
> **Found:** 2026-05-13 — surfaced by direct inspection of `docker logs development-easy-agent-1` after an OpenEMR-maintainer report. CATS campaign [`10f44930-413c-4ba0-805e-81e3195af83a`](http://localhost:8400/campaigns/10f44930-413c-4ba0-805e-81e3195af83a) was running concurrently and exercised `extract.php` 30 times across 20 runs, but did **not** flag the auth break. See "Why CATS didn't catch this earlier" below.
> **Reported:** 2026-05-13 (in-thread maintainer report; no external issue/PR opened).
> **Fixed:** 2026-05-13 — openemr commit `7b2b6c80d` ("fix(copilot): route extract.php through resolveIssuer() like agent.php").
> **Class:** JWT validation — issuer-claim drift between mint side and verify side (configuration-vs-code mismatch, not cryptographic).

## What broke

Every `POST /interface/modules/custom_modules/oe-module-clinical-copilot/public/extract.php` request from the panel came back with HTTP `200`, `Content-Type: text/event-stream`, and a bare body of `{"error":"unauthorized"}`. The proxy had flushed SSE headers before attempting the upstream POST; when the agent rejected the bearer with `401`, the SSE sink piped the JSON body through as if it were an SSE chunk. Result: the browser's `EventSource` saw an unparseable frame and the pipeline never started. The agent log showed:

```
JWT verification failed: unexpected "iss" claim value
err: ERR_JWT_CLAIM_VALIDATION_FAILED
```

The sibling `agent.php` route worked fine — same proxy, same agent, same JWT minter — which is what made the failure feel like a config drift rather than a credentials problem.

## Root cause (OpenEMR side)

`extract.php` (added after the centralized issuer-resolver was introduced) composed the JWT issuer from globals directly:

```php
$siteAddr = $globals->getString('site_addr_oath');     // "http://localhost:8300"  (OpenEMR's *self*-URL)
$webroot  = $globals->getWebRoot();                    // ""
$issuer   = $siteAddr . $webroot . '/oauth2/' . $siteId;
// → "http://localhost:8300/oauth2/default"
```

But the agent container was pinned (via `AGENT_JWT_ISSUER` env) to the **browser-facing** URL:

```
AGENT_JWT_ISSUER=https://localhost:9300/oauth2/default
```

The two strings differ in scheme (`http` vs `https`) and port (`8300` vs `9300`) — both are the same OpenEMR instance, but `site_addr_oath` is what OpenEMR sees *itself* as on the docker network, while the agent's expected issuer is the external URL the browser and the agent's JWKS-fetcher use. `jose`'s `jwtVerify` compares `iss` byte-for-byte, so the mismatch failed verification.

The sibling `agent.php` had already been migrated (openemr commit `744a888b6`) to use a shared helper, `AgentEndpointBootstrap::resolveIssuer($siteId)`, which honors an `OE_AGENT_JWT_ISSUER` override and falls back to the direct composition only when unset. `extract.php` was authored later and missed the helper — `git blame` shows it inlined the legacy composition pattern from the older `agent.php` revision.

The dev-stack compose files (`docker/development-easy/docker-compose.yml`) had the override set on the OpenEMR container side (`OE_AGENT_JWT_ISSUER=https://localhost:9300/oauth2/default`), so the helper *would* have produced the right string — `extract.php` just wasn't asking it.

## Resolution

Two changes in commit `7b2b6c80d`:

1. **`extract.php` now resolves the issuer through the shared helper**:

   ```php
   use OpenEMR\Modules\ClinicalCopilot\Bootstrap\AgentEndpointBootstrap;
   …
   $issuer = AgentEndpointBootstrap::resolveIssuer($siteId);
   ```

   Behavior is now identical to `agent.php`: read `OE_AGENT_JWT_ISSUER` if set, otherwise compose from globals. On the dev stack the override is set; on the digitalocean stack it isn't needed because the container's `site_addr_oath` already matches `AGENT_JWT_ISSUER`.

2. **New structural-regression test** at `tests/Tests/Isolated/Modules/ClinicalCopilot/Auth/IssuerResolutionConsistencyTest.php`. Data-provides over every browser-inbound mint entry point (`agent.php`, `extract.php`) and asserts both:
   - positively: the helper call is present;
   - negatively: the `$siteAddr . $webroot . '/oauth2/'` direct-composition regex is absent.

   The next sibling route that adds a mint will hit a red CI before it hits this same bug.

The agent verifier itself was left untouched. Iss validation stays strict, no permissive mode, no regex fallback — the bug was the mint side composing the wrong string, not the verify side being too strict.

Verification post-fix: a smoke-test against `/agent.php?action=echo` (which shares the same mint path) produced `200 text/event-stream` with `data: {"ok":true,…}`, and the agent log line was:

```
{"level":20,"component":"auth","fhirUser":"…","jti":"…","msg":"authenticated agent request"}
```

A runtime computation inside the openemr container confirmed both entry points now compose the byte-identical string `https://localhost:9300/oauth2/default`.

## Why CATS didn't catch this earlier / Why it surfaced now

CATS campaign `10f44930-413c-4ba0-805e-81e3195af83a` ran concurrently with this bug being live and fired `extract.php` 30 times across 20 runs. Every execution was judged `safe` and the campaign produced zero findings, zero vulnerability reports for the auth break. The gap is in CATS's response interpretation, not its attack surface:

- **Status-code-driven detection.** CATS's `output_filter` and judge treated `HTTP 200` as success. The proxy's pre-stream-error path leaks an `application/json` `{"error":"unauthorized"}` body under a `text/event-stream` content-type header — semantically a 401, but the wire status was 200 because SSE headers had already flushed. Nothing in CATS's pipeline cross-checked content-type against body shape or against the agent's own logs.
- **Red-team agent didn't replay the docx.** The 10 `400 invalid_trigger_source` rejections are CATS's red-team probing with malformed envelopes that never got far enough to mint a JWT, and the 20 `200` responses are the *non*-extract briefing path. The campaign exercised the extract-pipeline trigger but the JWT-mint hop's failure mode produced indistinguishable "agent saw something" output to the upstream caller.
- **No log-correlation pass.** A finding here would have required CATS to read `docker logs cats-target-agent` (or the langsmith trace), notice `ERR_JWT_CLAIM_VALIDATION_FAILED`, and tie it back to the execution. The agent-side observability is there, the orchestrator just doesn't consume it.

Detection-gap follow-ups (CATS-side, tracked separately):

1. Body-vs-content-type sanity check in `output_filter` — `application/json error envelope` under `text/event-stream` is a strong signal something is wrong even when the wire status is 200.
2. Optional agent-log scrape on each execution, looking for `ERR_JWT_*` / `unauthorized` / `rejected agent request` lines and attaching them to the execution record. Cheap because it's container-local.
3. Per-route smoke test as a campaign prelude: hit each mint entry point with a known-good envelope before running the red-team agent, and abort the campaign if any returns an auth-error body — this exact bug would have tripped that gate on probe #1.

How it surfaced: the OpenEMR maintainer noticed pipeline triggers silently failing during manual panel testing, read the agent container logs directly, saw the `iss` rejection, and traced it to `extract.php`. Out-of-band debugging, not CATS.

## Related

- [`2026-05-13-supervisor-chart-enriched-fanout-dos.md`](./2026-05-13-supervisor-chart-enriched-fanout-dos.md) — same campaign id (`10f44930-…`) was the actual CATS-surfaced finding from that day. Two separate OpenEMR bugs, only one of them detected by CATS.
- openemr commit `744a888b6` — original introduction of `AgentEndpointBootstrap::resolveIssuer()`, which `agent.php` adopted and `extract.php` should have at authoring time.
- openemr `tests/Tests/Isolated/Modules/ClinicalCopilot/ResolveIssuerTest.php` — existing contract test on the helper itself; the new `IssuerResolutionConsistencyTest` is the entry-point-side complement.
