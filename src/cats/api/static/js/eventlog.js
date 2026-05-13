// Live event stream renderer + campaign-detail page reactivity.
//
// Three concerns:
//   1. Append rows to #eventlog from the live SSE stream + a one-shot
//      backfill via /campaigns/<id>/timeline so reloads keep the log.
//   2. Update #stage-banner's avatar/label based on the kind of event
//      that just landed (orchestrator → red_team → judge → documentor).
//   3. Append + mutate rows in #runs-table on run_started / run_completed
//      so the run-status panel populates without a page reload.

(function () {
  "use strict";

  const MAX_ROWS = 50;

  function fmtTs(at) {
    if (!at) return new Date().toISOString().substring(11, 19);
    const m = String(at).match(/T(\d{2}:\d{2}:\d{2})/);
    return m ? m[1] : String(at).substring(11, 19);
  }

  function shortId(idLike) {
    if (!idLike) return "";
    return String(idLike).substring(0, 8);
  }

  function escapeHtml(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  // ----- Event-kind -> renderer ---------------------------------------
  //
  // Each entry returns:
  //   cls    — CSS modifier for the .kind column (color)
  //   label  — uppercase chip text
  //   body   — primary line of the row (one short phrase)
  //   meta   — optional second line (small grey detail)
  //
  // The body builder reads fields off env.payload. Missing fields fall
  // back to neutral strings so the row always renders even if a worker
  // forgot to set a key.
  const KINDS = {
    campaign_started: {
      cls: "agent-orch",
      label: "campaign · started",
      body: (p) => {
        const bits = [];
        if (p.selected_category) bits.push(p.selected_category);
        if (p.target_kind) bits.push(`target ${p.target_kind}`);
        if (p.budget_usd != null) bits.push(`$${p.budget_usd}`);
        return bits.join(" · ") || "campaign started";
      },
    },
    campaign_requested: {
      cls: "agent-orch",
      label: "orchestrator · planning",
      body: (p) =>
        p.budget_usd != null
          ? `picking attack mix · budget $${p.budget_usd}`
          : "picking attack mix",
    },
    plan_proposed: {
      cls: "agent-orch",
      label: "plan · proposed",
      body: (p) =>
        `${p.attempt_count ?? "?"} attempts ready for approval`,
    },
    plan_approved: {
      cls: "agent-orch",
      label: "plan · approved",
      body: (p) => `plan ${shortId(p.plan_id)} approved, dispatching`,
    },
    plan_failed: {
      cls: "verdict pass",
      label: "plan · failed",
      body: (p) => p.error || "orchestrator could not produce a plan",
    },
    run_started: {
      cls: "agent-red",
      label: "run · started",
      body: (p) =>
        p.technique && p.category
          ? `${p.category} · ${p.technique}${p.seed_idx != null ? " · seed " + p.seed_idx : ""}`
          : "run started",
    },
    attack_proposed: {
      cls: "agent-red",
      label: "attack · proposed",
      body: (p) => {
        if (p.stage === "mutator_passthrough") return "mutator · passthrough";
        if (p.title && p.technique) return `${p.technique} · ${p.title}`;
        return p.title || p.technique || p.note || "attack staged";
      },
    },
    attack_starting: {
      cls: "agent-red",
      label: "attack · sending",
      body: (p) => {
        const techn = p.technique
          ? `${p.category || "?"} · ${p.technique}`
          : "firing at target";
        return techn + " — awaiting target response…";
      },
      meta: (p) =>
        p.iteration ? `iteration ${p.iteration}` : null,
    },
    attack_executed: {
      cls: "agent-red attack",
      label: "attack · executed",
      body: (p) => {
        if (p.category && p.technique)
          return `${p.category} · ${p.technique}`;
        return "attack fired";
      },
      meta: (p) => {
        const bits = [];
        if (p.status_code != null)
          bits.push(`HTTP ${p.status_code}`);
        if (p.latency_ms != null) bits.push(`${p.latency_ms}ms`);
        if (p.filter_verdict) bits.push(`filter ${p.filter_verdict}`);
        if (p.iteration) bits.push(`iter ${p.iteration}`);
        return bits.join(" · ");
      },
    },
    judge_verdict_rendered: {
      cls: (p) =>
        "agent-judge verdict " +
        (p.verdict === "pass"
          ? "pass"
          : p.verdict === "fail"
          ? "fail"
          : ""),
      label: (p) => `verdict · ${p.verdict || "?"}`,
      body: (p) =>
        p.verdict === "pass"
          ? "attack passed — defense failed"
          : p.verdict === "fail"
          ? "attack failed — defense held"
          : p.rationale || `verdict ${p.verdict || "?"}`,
      meta: (p) => (p.rationale && p.verdict !== "pass" && p.verdict !== "fail" ? null : p.rationale || null),
    },
    finding_promoted: {
      cls: "agent-doc",
      label: "finding · promoted",
      body: (p) =>
        `[${(p.severity || "?").toUpperCase()}] ${p.title || "new finding"}`,
    },
    run_completed: {
      cls: "",
      label: "run · completed",
      body: (p) => {
        const spend =
          p.spend_usd != null
            ? `$${(p.spend_usd.toFixed ? p.spend_usd.toFixed(4) : p.spend_usd)}`
            : "—";
        return `${p.attacks_fired ?? "?"} attacks · ${spend}`;
      },
    },
    campaign_halted: {
      cls: "",
      label: "campaign · halted",
      body: (p) => p.reason || "halted",
    },
  };

  function renderRow(env) {
    const spec = KINDS[env.kind] || {
      cls: "",
      label: env.kind,
      body: () => "(unknown event)",
    };
    const payload = env.payload || {};
    const cls =
      typeof spec.cls === "function" ? spec.cls(payload) : spec.cls;
    const label =
      typeof spec.label === "function" ? spec.label(payload) : spec.label;
    const body =
      typeof spec.body === "function" ? spec.body(payload) : spec.body;
    const meta =
      spec.meta
        ? typeof spec.meta === "function"
          ? spec.meta(payload)
          : spec.meta
        : null;

    const row = document.createElement("div");
    row.className = "row fresh";
    row.innerHTML =
      `<div class="ts">${escapeHtml(fmtTs(env.at))}</div>` +
      `<div class="kind ${escapeHtml(cls)}">${escapeHtml(label)}</div>` +
      `<div class="body-wrap">` +
        `<div class="body">${escapeHtml(body)}</div>` +
        (meta ? `<div class="row-meta">${escapeHtml(meta)}</div>` : "") +
      `</div>` +
      `<div class="id">${escapeHtml(shortId(env.run_id || env.campaign_id))}</div>`;
    return row;
  }

  // ----- Stage banner -------------------------------------------------
  //
  // Event-kind -> which avatar to show next. `null` means "don't
  // change" (purely informational events). The mapping reflects the
  // pipeline ordering: orchestrator → red_team → judge → documentor.
  const STAGE_BY_KIND = {
    campaign_requested: "orchestrator",
    plan_proposed: "orchestrator",
    plan_approved: "red_team",
    plan_failed: "failed",
    run_started: "red_team",
    attack_starting: "red_team",
    attack_executed: "judge",
    judge_verdict_rendered: "documentor",
    finding_promoted: "documentor",
    run_completed: "complete",
    campaign_halted: "complete",
  };
  const STAGE_META = {
    orchestrator: {
      label: "Orchestrator planning",
      img: "/static/img/orchestrator.png",
      pulse: true,
    },
    red_team: {
      label: "Red Team attacking",
      img: "/static/img/red-team.png",
      pulse: true,
    },
    judge: {
      label: "Judge evaluating",
      img: "/static/img/judge.png",
      pulse: true,
    },
    documentor: {
      label: "Documentor writing",
      img: "/static/img/documentor.png",
      pulse: true,
    },
    complete: {
      label: "Campaign complete",
      img: "/static/img/judge.png",
      pulse: false,
    },
    failed: {
      label: "Campaign failed",
      img: "/static/img/orchestrator.png",
      pulse: false,
    },
  };

  function updateStageFromEvent(env) {
    const banner = document.getElementById("stage-banner");
    if (!banner) return;
    const nextKey = STAGE_BY_KIND[env && env.kind];
    if (!nextKey) return;
    const meta = STAGE_META[nextKey];
    if (!meta) return;
    if (banner.getAttribute("data-stage-key") === nextKey) return;
    banner.setAttribute("data-stage-key", nextKey);
    const avatar = banner.querySelector(".stage-avatar");
    const labelEl = document.getElementById("stage-label-text");
    const pulseEl = document.getElementById("stage-pulse");
    if (avatar) {
      // Crossfade swap.
      avatar.classList.add("swapping");
      setTimeout(() => {
        avatar.src = meta.img;
        avatar.classList.remove("swapping");
      }, 150);
    }
    if (labelEl) labelEl.textContent = meta.label;
    if (pulseEl) {
      pulseEl.style.display = meta.pulse ? "" : "none";
    }
  }

  // ----- Runs table mutations -----------------------------------------
  //
  // Append a row on run_started; update the row on run_completed.
  // No-op on pages that don't have a runs table (the global event log).
  function findRunsTable() {
    return document.getElementById("runs-table");
  }

  function updateRunsCountMeta() {
    const meta = document.getElementById("run-status-meta");
    const table = findRunsTable();
    if (!meta || !table) return;
    const n = table.querySelectorAll("tbody tr").length;
    meta.textContent = `${n} run${n === 1 ? "" : "s"}`;
  }

  function showRunsTable() {
    const table = findRunsTable();
    const empty = document.getElementById("runs-empty");
    if (table) table.style.display = "";
    if (empty) empty.style.display = "none";
  }

  function handleRunStarted(env) {
    const table = findRunsTable();
    if (!table || !env || !env.run_id) return;
    const campaignId = table.getAttribute("data-campaign-id");
    if (table.querySelector(`tr[data-run-id="${env.run_id}"]`)) return;
    const tbody = table.querySelector("tbody");
    if (!tbody) return;
    showRunsTable();
    const p = env.payload || {};
    const tech =
      p.category && p.technique ? `${p.category} · ${p.technique}` : "—";
    const ts = fmtTs(env.at);
    const tr = document.createElement("tr");
    tr.setAttribute("data-run-id", env.run_id);
    tr.className = "fresh";
    tr.innerHTML =
      `<td class="mono"><a class="nav-link" href="/campaigns/${escapeHtml(campaignId)}/runs/${escapeHtml(env.run_id)}">${escapeHtml(shortId(env.run_id))}</a></td>` +
      `<td class="run-status-cell"><span class="dot amber pulse"></span> <span class="run-status-text">running</span></td>` +
      `<td class="run-technique mono">${escapeHtml(tech)}</td>` +
      `<td class="num run-attacks">0</td>` +
      `<td class="num mono run-spend">$0.0000</td>` +
      `<td class="num mono run-slowest">—</td>` +
      `<td class="num muted">${escapeHtml(ts)}</td>`;
    tbody.insertBefore(tr, tbody.firstChild);
    updateRunsCountMeta();
  }

  function handleRunCompleted(env) {
    const table = findRunsTable();
    if (!table || !env || !env.run_id) return;
    const tr = table.querySelector(`tr[data-run-id="${env.run_id}"]`);
    if (!tr) return;
    const p = env.payload || {};
    const status = (p.status === "failed" ? "failed" : "completed");
    const statusCell = tr.querySelector(".run-status-cell");
    if (statusCell) {
      const dotCls = status === "failed" ? "red" : "green";
      statusCell.innerHTML =
        `<span class="dot ${dotCls}"></span> <span class="run-status-text">${escapeHtml(status)}</span>`;
    }
    if (p.attacks_fired != null) {
      const cell = tr.querySelector(".run-attacks");
      if (cell) cell.textContent = String(p.attacks_fired);
    }
    if (p.spend_usd != null) {
      const cell = tr.querySelector(".run-spend");
      if (cell)
        cell.textContent =
          "$" +
          (p.spend_usd.toFixed ? p.spend_usd.toFixed(4) : p.spend_usd);
    }
    tr.classList.add("fresh");
  }

  function handleAttackExecuted(env) {
    // Bump the attacks-fired count on the run row, if present.
    const table = findRunsTable();
    if (!table || !env || !env.run_id) return;
    const tr = table.querySelector(`tr[data-run-id="${env.run_id}"]`);
    if (!tr) return;
    const cell = tr.querySelector(".run-attacks");
    if (cell) {
      const n = parseInt(cell.textContent || "0", 10);
      cell.textContent = String((isNaN(n) ? 0 : n) + 1);
    }
    // Track the slowest attack so the operator sees cost-amplification
    // signals at a glance. ≥60s flips the cell amber to match the
    // server-rendered threshold.
    const p = env.payload || {};
    if (p.latency_ms != null) {
      const slow = tr.querySelector(".run-slowest");
      if (slow) {
        const current = parseFloat(slow.dataset.maxMs || "0");
        const incoming = Number(p.latency_ms);
        if (!isNaN(incoming) && incoming > current) {
          slow.dataset.maxMs = String(incoming);
          slow.textContent = (incoming / 1000).toFixed(1) + "s";
          if (incoming >= 60000) slow.classList.add("amber");
          else slow.classList.remove("amber");
        }
      }
    }
  }

  function applyMutations(env) {
    if (!env || !env.kind) return;
    if (env.kind === "run_started") handleRunStarted(env);
    else if (env.kind === "run_completed") handleRunCompleted(env);
    else if (env.kind === "attack_executed") handleAttackExecuted(env);
  }

  // ----- Backfill + live stream wiring --------------------------------

  function attach(eventlog) {
    const url = eventlog.getAttribute("data-sse");
    if (!url) return;
    if (typeof EventSource === "undefined") return;

    let placeholderCleared = false;
    function clearPlaceholder() {
      if (placeholderCleared) return;
      placeholderCleared = true;
      eventlog.querySelectorAll(".empty").forEach((el) => el.remove());
    }

    // De-dupe key for backfilled events: the timeline returns the same
    // logical events the live SSE stream will re-emit if the worker is
    // still running. Build a coarse signature from kind + run_id + at.
    const seen = new Set();
    function signatureOf(env) {
      const at = (env && env.at) || "";
      const run = (env && env.run_id) || "";
      const kind = (env && env.kind) || "";
      return `${kind}|${run}|${at}`;
    }
    function rememberEnv(env) {
      seen.add(signatureOf(env));
    }
    function isDuplicate(env) {
      return seen.has(signatureOf(env));
    }

    // Plan-lifecycle events change so much server-rendered state
    // (status pill, "Pending Approval" CTA, cost rollup) that the
    // simplest reliable refresh is a one-shot page reload when one
    // lands. Now that the event log + stage banner survive reloads,
    // this is cosmetically fine. Lifecycle kinds the campaign-detail
    // page should react to:
    const RELOAD_ON = new Set([
      "plan_proposed",
      "plan_approved",
      "plan_failed",
      "finding_promoted",
    ]);
    let reloadScheduled = false;
    function scheduleReload() {
      if (reloadScheduled) return;
      reloadScheduled = true;
      setTimeout(function () {
        window.location.reload();
      }, 250);
    }

    function maybeBackfill() {
      const m = url.match(/^\/events\/([0-9a-f-]+)$/i);
      if (!m) return Promise.resolve();
      return fetch(`/campaigns/${m[1]}/timeline`, { credentials: "same-origin" })
        .then((r) => (r.ok ? r.json() : []))
        .then((events) => {
          if (!Array.isArray(events) || events.length === 0) return;
          clearPlaceholder();
          // Backfill is append-oldest-first; new rows from the live
          // source go to the top via insertBefore(firstChild), so the
          // final ordering is newest-at-top across both sources.
          events.forEach((env) => {
            rememberEnv(env);
            const row = renderRow(env);
            // Don't blink the backfill rows — they're history.
            row.classList.remove("fresh");
            eventlog.insertBefore(row, eventlog.firstChild);
            while (eventlog.children.length > MAX_ROWS) {
              eventlog.removeChild(eventlog.lastChild);
            }
            // Drive the stage avatar to the latest historical state
            // so the page paints with the right active agent.
            updateStageFromEvent(env);
          });
        })
        .catch(() => {});
    }

    let src = null;
    function openLiveStream() {
      src = new EventSource(url);
      src.onmessage = function (e) {
        let env;
        try {
          env = JSON.parse(e.data);
        } catch (err) {
          return;
        }
        if (isDuplicate(env)) return;
        rememberEnv(env);
        clearPlaceholder();
        const row = renderRow(env);
        eventlog.insertBefore(row, eventlog.firstChild);
        while (eventlog.children.length > MAX_ROWS) {
          eventlog.removeChild(eventlog.lastChild);
        }
        updateStageFromEvent(env);
        applyMutations(env);
        if (env && env.kind && RELOAD_ON.has(env.kind)) {
          scheduleReload();
        }
      };
      src.onerror = function () {};
    }

    maybeBackfill().then(openLiveStream);

    window.addEventListener("beforeunload", function () {
      if (src) src.close();
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll("#eventlog[data-sse]").forEach(attach);
  });
})();
