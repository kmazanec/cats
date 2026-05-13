// Live event stream renderer.
//
// Opens an EventSource against the URL declared on `#eventlog[data-sse]`
// and prepends a styled .row for each incoming event. The .eventlog CSS
// already styles .ts / .kind / .body / .id; we mirror that structure
// here rather than bring in HTMX's SSE extension (which expects pre-
// rendered fragments on the wire).
//
// Cap the log at MAX_ROWS so a long-running campaign doesn't blow out
// the DOM. New rows get a `.fresh` class that the CSS fades out.

(function () {
  "use strict";

  const MAX_ROWS = 50;

  function fmtTs(at) {
    if (!at) return new Date().toISOString().substring(11, 19);
    // ISO from the server -> HH:MM:SS (UTC, matches the rest of the UI).
    const m = String(at).match(/T(\d{2}:\d{2}:\d{2})/);
    return m ? m[1] : String(at).substring(11, 19);
  }

  function shortId(idLike) {
    if (!idLike) return "";
    return String(idLike).substring(0, 8);
  }

  // Map event kind -> (kind class for color, human label, body builder).
  // The body builder reads fields off env.payload; missing fields fall
  // back to neutral strings so the row always renders.
  const KINDS = {
    campaign_started: {
      cls: "",
      label: "campaign · started",
      body: (p) => {
        const bits = [];
        if (p.selected_category) bits.push(p.selected_category);
        if (p.target_kind) bits.push(`target ${p.target_kind}`);
        if (p.budget_usd != null) bits.push(`$${p.budget_usd}`);
        return bits.join(" · ") || "campaign started";
      },
    },
    run_started: {
      cls: "",
      label: "run · started",
      body: (p) => (p.technique ? `technique ${p.technique}` : "run started"),
    },
    attack_proposed: {
      cls: "attack",
      label: "attack · proposed",
      body: (p) => {
        if (p.stage === "mutator_passthrough") return "mutator · passthrough";
        if (p.title && p.technique) return `${p.technique} · ${p.title}`;
        return p.title || p.technique || p.note || "attack staged";
      },
    },
    attack_executed: {
      cls: "attack",
      label: "attack · executed",
      body: (p) =>
        `target ${p.status_code ?? "?"} · ${p.latency_ms ?? "?"}ms` +
        (p.filter_verdict ? ` · filter ${p.filter_verdict}` : ""),
    },
    judge_verdict_rendered: {
      cls: (p) =>
        "verdict " +
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
    },
    finding_promoted: {
      cls: "",
      label: "finding · promoted",
      body: (p) =>
        `[${(p.severity || "?").toUpperCase()}] ${p.title || "new finding"}`,
    },
    run_completed: {
      cls: "",
      label: "run · completed",
      body: (p) =>
        `${p.attacks_fired ?? "?"} attacks · $${(p.spend_usd ?? 0).toFixed
          ? p.spend_usd.toFixed(4)
          : p.spend_usd}`,
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

    const row = document.createElement("div");
    row.className = "row fresh";
    row.innerHTML =
      `<div class="ts"></div>` +
      `<div class="kind ${cls}"></div>` +
      `<div class="body"></div>` +
      `<div class="id"></div>`;
    row.querySelector(".ts").textContent = fmtTs(env.at);
    row.querySelector(".kind").textContent = label;
    row.querySelector(".body").textContent = body;
    row.querySelector(".id").textContent = shortId(
      env.run_id || env.campaign_id,
    );
    return row;
  }

  function attach(eventlog) {
    const url = eventlog.getAttribute("data-sse");
    if (!url) return;
    if (typeof EventSource === "undefined") return;

    // Remove any "waiting for events" placeholder once the stream is
    // open — keep it visible while we're connecting so a torn-down
    // backend still reads as "nothing yet" rather than "broken".
    let placeholderCleared = false;
    function clearPlaceholder() {
      if (placeholderCleared) return;
      placeholderCleared = true;
      eventlog
        .querySelectorAll(".empty")
        .forEach((el) => el.remove());
    }

    // Plan-lifecycle events change so much server-rendered state
    // (status pill, "Pending Approval" CTA, run list, cost rollup)
    // that the simplest reliable refresh is a one-shot page reload
    // when one lands. Deduplicate so a rapid auto-approve flow
    // (plan_proposed + plan_approved in <100ms) reloads at most
    // once. Lifecycle kinds the campaign-detail page should react
    // to: anything that flips the plan pill or seeds a new run.
    const RELOAD_ON = new Set([
      "plan_proposed",
      "plan_approved",
      "plan_failed",
      "finding_promoted",
      "run_completed",
    ]);
    let reloadScheduled = false;
    function scheduleReload() {
      if (reloadScheduled) return;
      reloadScheduled = true;
      // Small delay so the worker's transaction commits before we
      // re-read the campaign + plan rows on reload.
      setTimeout(function () {
        window.location.reload();
      }, 250);
    }

    const src = new EventSource(url);
    src.onmessage = function (e) {
      let env;
      try {
        env = JSON.parse(e.data);
      } catch (err) {
        return;
      }
      clearPlaceholder();
      const row = renderRow(env);
      eventlog.insertBefore(row, eventlog.firstChild);
      while (eventlog.children.length > MAX_ROWS) {
        eventlog.removeChild(eventlog.lastChild);
      }
      if (env && env.kind && RELOAD_ON.has(env.kind)) {
        scheduleReload();
      }
    };
    // Don't spam the console on transient reconnects — EventSource
    // retries on its own.
    src.onerror = function () {};
    // Detach on page unload so we don't leak the connection.
    window.addEventListener("beforeunload", function () {
      src.close();
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    document
      .querySelectorAll("#eventlog[data-sse]")
      .forEach(attach);
  });
})();
