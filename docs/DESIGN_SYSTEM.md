# CATS Design System

> Internal tool. CISO-facing. **Not** a marketing surface.
> Optimize for information density and operator throughput over visual delight.

This document is the source of truth for any UI work in CATS. Every component
in the dashboard, every email/Slack export, every embedded chart should
trace back to a rule here. If a screen needs to do something this guide
doesn't cover, the guide is incomplete — fix it here first.

The canonical visual reference is
[`cats-architecture-defense.html`](./cats-architecture-defense.html); start
there if you want to see the language applied end-to-end.

---

## 1. Principles

1. **Information density beats whitespace.** Operators triage findings; a
   dashboard that shows 4 cards on a 1440px screen is broken. Default to
   compact spacing, small font sizes, and tabular layouts. Whitespace is
   used for grouping, never for breathing room.
2. **Dark mode is the default and the only mode.** This tool is run for
   hours at a time in low-light SOC and on-call contexts. There is no
   light theme.
3. **Every UI element communicates information.** Decoration that doesn't
   carry signal — gradient buttons, hero illustrations, "delightful"
   micro-interactions — is not allowed. Pulses, blinks, and color shifts
   are reserved for state changes the operator must notice.
4. **Color is signal.** Amber means action / adversarial / attention.
   Cyan means platform / healthy / passive read. Red means failure
   requiring response. Green means a defense held. Violet means stored
   state. Gray means external/inert. Never use color decoratively.
5. **Monospace is structural.** Identifiers (IDs, paths, models, codes),
   metrics, timestamps, and labels render in JetBrains Mono. Prose renders
   in IBM Plex Sans. The two together create the CI/terminal feel; one
   without the other becomes either a website or a log file.
6. **Default to terminal grammar.** Section labels are uppercase mono with
   wide tracking and a leading rule (`— SECTION · NAME`). Crumbs use `/`
   separators. Pagination uses `01 / 06`. Status uses `OK · ERR · WARN`.
7. **Audit trail is visible, always.** Every action that touches a target
   shows the actor, target, and time on the same screen. Trust boundaries
   show their own provenance — a "fired campaign" tile shows *who* fired
   it without you having to click.
8. **Reversibility legibility.** Anything that costs money, calls a model,
   or attacks a live system shows budget and provenance before it runs.
   Confirmation dialogs are rare; **inline budget previews are the norm**.

---

## 2. Color tokens

All colors live as CSS variables. The dashboard imports them from
`/static/css/tokens.css` (or inlines them in `base.html` while the asset
pipeline is bootstrapping). Do not introduce new color values without
adding a token here.

### 2.1 Surfaces

| Token | Hex | Use |
|---|---|---|
| `--bg`   | `#0a0e1a` | Page background. The deepest layer. |
| `--bg-2` | `#0f1424` | Card / panel surface. One step up from page. |
| `--bg-3` | `#131a2e` | Nested surface (a code block inside a card, a header row inside a table). |
| `--line`   | `#1e2740` | Default 1px divider. Use everywhere a separation is needed. |
| `--line-2` | `#2a3553` | Stronger divider — major panel boundaries, sticky table headers. |

### 2.2 Ink (text)

| Token | Hex | Use |
|---|---|---|
| `--ink`   | `#e7ecf5` | Primary text — values, identifiers, table cells. |
| `--ink-2` | `#aab3c6` | Secondary text — prose, descriptions, supporting labels. |
| `--ink-3` | `#6b7591` | Tertiary / muted — eyebrow labels, table headers, timestamps. |
| `--ink-4` | `#44506a` | Quaternary / inactive — disabled controls, dividers' adjacent text. |

The four-step ink ladder is intentional. Use it to communicate hierarchy
*without* changing font size — most table cells should be `--ink`, the
column headers `--ink-3`, and a "last seen 3m ago" timestamp `--ink-4`.

### 2.3 Semantic accents

| Token | Hex | Meaning | Use |
|---|---|---|---|
| `--amber`      | `#f5a524` | **Action / adversarial / attention.** | Adversarial agents (Red Team, Mutator), severity badges, fired-campaign indicators, primary CTA, the brand dot. |
| `--amber-2`    | `#fb923c` | Amber emphasis | Used sparingly for hover states or the highest-volume tier in scale tables. |
| `--amber-soft` | `#f59e0b22` | Amber background tint | Subtle row highlights for "needs attention" rows. |
| `--cyan`       | `#38bdf8` | **Platform / healthy / passive.** | Judge, Documentation Agent, healthy-defense verdicts, navigation cursors, identifiers in tables, the platform half of the brand. |
| `--cyan-2`     | `#67e8f9` | Cyan emphasis | Hover / focus rings on cyan-keyed elements. |
| `--cyan-soft`  | `#38bdf81f` | Cyan background tint | Quote/callout backgrounds (cf. q-list style). |
| `--green`      | `#4ade80` | **Defense held / pass.** | Judge verdicts of "fail (attack failed = defense held)", green coverage cells. |
| `--red`        | `#ef4444` | **Failure requiring response.** | Critical findings, halt states, Judge errors, breach indicators. |
| `--violet`     | `#a78bfa` | **Stored state / data plane.** | Postgres / Redis nodes in diagrams, the Storage swatch. |
| `--ink-3` (gray) | `#6b7591` | External / inert | Target Co-Pilot in diagrams, third-party services. |

**Rules for combining:**

- Never put amber and red next to each other without a 1px `--line`
  between — they vibrate.
- Cyan and green together is fine; they form the "all good" cluster.
- Amber + cyan = the canonical CATS dichotomy (adversarial vs. platform).
  This is the only color pairing that's used decoratively, and only in
  the brand mark and gradient dividers.

### 2.4 Atmosphere

| Token | Value | Use |
|---|---|---|
| `--grid` | `rgba(255,255,255,0.025)` | The 48px page grid (very faint). Applied as a fixed body::before with a radial mask. |

The page grid is the only decorative element allowed. It makes the dark
surface feel like instrumented space, not a flat background.

---

## 3. Typography

Two families, both Google Fonts, preloaded in `<head>`:

```html
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:ital,wght@0,300;0,400;0,500;0,600;0,700;1,400&family=JetBrains+Mono:ital,wght@0,300;0,400;0,500;0,600;0,700;1,400&display=swap" rel="stylesheet">
```

### 3.1 IBM Plex Sans — prose

- Used for sentences, descriptions, button labels, paragraphs.
- Default weight: 400; light weight 300 for long-form supporting text
  (`.subtitle`, descriptions inside cards).
- Letter spacing: `0.005em` body default. Do not tighten.

### 3.2 JetBrains Mono — structural

- Used for: identifiers, IDs, paths, URLs, model names, prices, percentages,
  timestamps, durations, eyebrow labels, section crumbs, table headers,
  metric numbers in cards, code snippets, pagination, status text.
- Default weight: 400. Use 500 for emphasis on tabular data (e.g. a
  hot value), 600–700 for hero numerics.

### 3.3 Type scale

| Role | Family | Size | Weight | Tracking | Use |
|---|---|---|---|---|---|
| Hero | Mono | 64–240px (clamp) | 700 | -0.025–-0.04em | Splash / cover only |
| Title H1 | Mono | 42–52px | 600 | -0.02em | Page title |
| Title H2 | Mono | 28–34px | 600 | -0.015em | Section title |
| Title H3 | Mono | 18–20px | 500 | normal | Card title |
| Eyebrow | Mono | 11px | 500 | 0.22em uppercase | Section labels (`— 01 · NAME`) |
| Crumb / chrome | Mono | 10.5–11px | 400 | 0.18em uppercase | Top/bottom chrome |
| Metric XL | Mono | 52px | 700 | -0.03em | Card hero number |
| Metric L | Mono | 28px | 600 | -0.02em | Inline KPI |
| Metric M | Mono | 18px | 500 | normal | Tabular numeric cells |
| Body | Sans | 14.5–15.5px | 300–400 | normal | Default prose |
| Body small | Sans | 13–14px | 300–400 | normal | Card descriptions |
| Caption | Mono | 10.5–11px | 400 | 0.18em uppercase | Legends, footnotes |
| Code inline | Mono | 0.86–0.92em | 400 | normal | `code` elements inside body text |

### 3.4 Rules

- **Eyebrow has a leading rule.** `::before` is a 22×1px amber line, then a
  10px gap, then the label. This is the canonical section opener.
- **Mono uppercase tracks 0.18–0.24em.** Anything below that looks
  cramped; anything above looks decorative. Stay in the band.
- **Mono is never italic** except for `<em>` highlights inside prose,
  which override to non-italic + amber. Italic mono is a hard no.
- **Sans is never below 13px** except for legends and footnotes
  (which switch to mono).

---

## 4. Layout

### 4.1 Page chrome

Every full-screen surface has two chrome strips: top and bottom.

**Top chrome (`.chrome-top`):** brand mark on the left, system info on the
right. Mono uppercase 11px, `--ink-3`. Brand mark is a 1px amber-glow
pulsing dot + the product name in inverse-tracked mono. System info reads
like a CI build header: `Env · prod  Build · 0042  2026-05-11`.

**Bottom chrome (`.chrome-bottom`):** breadcrumbs on the left,
pagination/page indicator on the right. Mono uppercase 10.5px,
`--ink-4`. Breadcrumbs use slash separators in `--line-2`.

Page padding: `56px 72px 84px` on desktop, collapsing to `40px 48px 76px`
under 1100px. The bottom padding accommodates the bottom chrome strip.

### 4.2 Grids

The page has an invisible 48px grid (via `body::before`). All major
panel widths and gaps snap to multiples of 8px, with 24/32/48/64 being
the canonical gap values. Never use 16 alone — it reads "loose" in this
design language.

### 4.3 Containers

Cards have:

- 1px `--line` border
- `--bg-2` background (or a 180deg linear-gradient to subtly fade
  toward `rgba(15,20,36,0.4)` for the "panel with glow at the top" feel)
- A 2px accent rule along the top edge (`::before`) — amber for
  adversarial-keyed cards, cyan for platform-keyed, a left-to-right
  gradient for "mixed" / router-style cards
- 24×26px internal padding by default; 14×16px for compact tabular cards
- No border-radius. **CATS UI has zero rounded corners.** This is a
  deliberate choice — rounded corners read consumer-friendly.

### 4.4 Density modes

Three density modes, switchable per surface:

- **Cozy** — 14×16px row padding, 14.5px body. Triage list, finding
  detail. Default for human-read surfaces.
- **Compact** — 10×12px row padding, 13px body. Run table, attack
  execution log. The Spotify-of-security-data view.
- **Mono-only** — 8×12px row padding, 12.5px mono. Trace view, raw event
  log. No prose; only structured data.

A density toggle in the top chrome (`COZY · COMPACT · MONO`) is allowed
but not required; sensible default per surface is more important than the
toggle existing.

---

## 5. Components

This list grows with the dashboard. Every component documented here has
a corresponding CSS class or HTMX partial in
`src/cats/api/templates/`.

### 5.1 Eyebrow label

```html
<span class="eyebrow">01 · Rationale</span>
```

Mono 11px uppercase amber with leading 22×1px rule. Use to open every
section above an H2.

### 5.2 Stat strip

A horizontal row of 2–4 metrics separated by 1px vertical rules; the
top border is a 1px `--line` separator from the section above. Used to
front-load a screen with the numbers that matter.

```
HERO NUMBER     │     HERO NUMBER     │     HERO NUMBER
short caption.  │     short caption.  │     short caption.
```

Numbers in mono 52px amber; captions in 13px sans `--ink-2`. Caption
allowed one `<strong>` per stat which renders `--ink` 500-weight.

### 5.3 Decision list

A vertical list of indexed claims with a left mono index column
(`D · 01`, `D · 02`) in amber 12px and a body in sans 18px light.
1px `--line` separator between items, last one borderless. Use for
ADRs, design decisions surfaced in the UI, and "why this finding"
explanations.

### 5.4 Callout / quote list

A 2px cyan left border, soft cyan-tinted gradient background fading to
transparent at 60%, mono uppercase cyan 10.5px eyebrow above each item,
sans 14.5px body below. Use for open questions, follow-ups, and the
"discuss with the team" panel.

### 5.5 Check list

A vertical list with a 18×18px amber-bordered checkbox to the left of
each item, body in sans 15.5px light, 1px `--line` between items.
Use for "what shipped" / acceptance criteria / regression-gate status.

Variations: when the box has an internal amber check mark (`::after`
rotated arrow) the item reads "complete." When the box is empty, it's
"pending." Both states use amber — red is reserved for failures, not
pending state.

### 5.6 Scale / KPI table

A bordered table for numeric scaling data. Header row in `--bg-3`,
mono uppercase 10.5px `--ink-3`. Body rows mono 13px. Three column
template: `stage label | description | numeric cost`. Cost cells colored
by tier — green / cyan / amber / amber-bold — to encode escalation.

### 5.7 Pill / tag

Inline mono 10–11px uppercase letters in a 3×9px box. Two variants:

- **Solid amber:** `--bg` text on `--amber` background — used for the
  primary tag of a section (`<span class="tag">Ship</span>`).
- **Solid cyan:** `--bg` text on `--cyan` background — used for the
  secondary tag (`<span class="tag">Discuss</span>`).

### 5.8 Status dot

A 6–10px disc with a 0–12px outer glow:

| Variant | Meaning |
|---|---|
| Amber + glow + 2.4s pulse | Active / brand mark / live signal |
| Cyan + glow | Healthy / passive listener |
| Green | Pass |
| Red | Halt / breach |
| Gray (`--ink-4`) | Inactive |

### 5.9 Diagram nodes (SVG)

When embedding a system diagram inline (not via an image asset):

- Adversarial nodes: `--amber` stroke on `--bg-3` fill, label in mono
  amber.
- Platform nodes: `--cyan` stroke, label cyan.
- Storage nodes: `--violet` stroke, label violet.
- External nodes: `--ink-3` stroke, label `--ink-3`.
- Edges: 1.2–1.5px stroke, marker-end arrows in the same color family as
  the edge's destination.
- Labels: mono 11px, uppercase tracking 0.16em.

### 5.10 Tables (operator)

For finding lists, run lists, attack-execution tables:

- Header row in `--bg-3`, mono uppercase 10.5px `--ink-3`, 14×16px
  padding.
- Body rows in sans 14px `--ink`, 12×16px padding; mono used selectively
  for ID columns, timestamps, model names, cost columns.
- Zebra striping is **not** used. Distinction is by `--line` row
  borders only.
- Hover state: row gets a 1px `--line-2` top + bottom and a
  `--amber-soft` background tint. Cursor is `default` unless the row
  is clickable.
- Status column always renders as a status dot + label, never as a
  raw badge.

### 5.11 Buttons

Two variants, both rectangular (no radius), both with 12×20px padding.

- **Primary** (`button.btn`): 1px `--amber` border, `--amber` text on
  `--bg-2` background. Hover: invert (amber background, `--bg` text).
  Use for the single primary CTA on a screen.
- **Secondary** (`button.btn.ghost`): 1px `--line-2` border, `--ink`
  text, `--bg-2` background. Hover: `--line` → `--ink-3` border.
- **Destructive** (`button.btn.danger`): 1px `--red` border, `--red`
  text. Hover: `--red` background, `--bg` text. Reserved for halt /
  delete.

A button is never used for navigation. Use a link with a `→` glyph
instead.

### 5.12 Inputs

- 1px `--line-2` border, `--bg-3` fill, `--ink` text, mono 13px for
  text inputs that take an identifier (project URL, attack id, run id),
  sans 14px for free-form text.
- No placeholders — use a mono uppercase label above the input
  instead.
- Focus: border becomes `--cyan`, with a 1px `--cyan-soft` glow.
- Errors: border `--red`, helper text below in `--red` sans 13px.

### 5.13 Charts

- Background `--bg-2` with the page grid showing through.
- Axes: 1px `--line` lines, tick labels in mono 10.5px `--ink-3`.
- Series: amber for adversarial / attack-volume; cyan for platform /
  successful-defense; green for "fix held"; red for spikes that need
  attention.
- Never use a legend if a label can be placed inline next to the series.
- Sparklines are stroke-only, never filled. Bar charts are filled with
  no border.

---

## 6. Motion

Motion in CATS is reserved for **state change the operator must notice**.

- The brand-dot pulse (2.4s) is the only ambient motion — it confirms
  "the page is live, you're not looking at a stale screenshot."
- A cursor blink (1.05s) is used on terminal-style title splashes only.
- Page/route transitions: 380ms opacity + 24px translateX
  ease-out — fast enough to feel like a console redraw, not a wipe.
- Hover transitions: 220ms ease on background/border. No transform on
  hover except for the dots/tabs `background` shift.
- A newly arrived row in a live table fades in over 200ms and is
  underlined by a 1px amber-soft bar for 1.5s, then fades to default.
- **No bounce, no spring, no parallax, no scroll-jacking.**

---

## 7. Iconography

CATS uses very few icons. When one is needed, prefer single-stroke
geometric glyphs at 1.2–1.5px stroke, currentColor, no fill. The
canonical reference set is [Lucide](https://lucide.dev) at 14–18px,
recolored via CSS to whichever ink/accent token applies.

The dot, the dash, the arrow, the slash — these four glyphs (rendered
as monospace text characters) carry most of the visual load. Reach for
them before reaching for an icon.

---

## 8. Voice & copy

- Sentences are short. Periods are cheap.
- Identifiers are bare — `run 9af2 · injection · pass` beats
  "Run 9af2 successfully passed for the injection category."
- Numbers are absolute first, percentages second.
  `12 / 12 bypassed (100%)` not `100% of 12 defenses bypassed`.
- Time is relative for recent (`3m ago`) and absolute beyond an hour
  (`2026-05-11 14:32 UTC`).
- Never use exclamation points. Never use emoji.
- "Critical" is a severity label, never an adjective. Don't write
  "this is a critical change" — write "severity: critical" or use a
  red status dot.
- Confirmation copy is mechanical: "Fire campaign against
  `prod · openemr-copilot` (budget $4.20)?" — show the operand, show the
  cost, show the consequence. Never "Are you sure?"

---

## 9. Anti-patterns

These break the language. If you see them in a PR, push back.

- Rounded corners on any element.
- Gradients used as decoration (gradients are reserved for top-edge
  accent rules and a couple of named diagram backgrounds).
- Drop shadows. CATS has none. Elevation is conveyed by background
  step (`--bg` → `--bg-2` → `--bg-3`), not by shadow.
- Emoji or color-only icons.
- "Empty states" with illustrations. An empty table shows a single
  mono line: `no findings · click [fire campaign] above to start`.
- Big white CTAs. Inverse-button on the page = wrong tool.
- Hero illustrations of any kind.
- Marketing copy: "Powerful", "Seamless", "Effortless" — banned.
- Modal dialogs except for one thing: critical-severity human
  approval. Everything else is inline.
- Toast notifications. Use the audit log feed instead.
- Light mode anything. There is no light mode.

---

## 10. Application

When building a new surface:

1. Start from one of the canonical layouts in
   `cats-architecture-defense.html` (hero stat, two-column decision/
   principles, diagram + legend, three-column comparison, check/quote
   panel pair).
2. Wire up the chrome strips first — top brand+sysline, bottom crumb+
   page indicator. They orient the operator before any content loads.
3. Lead with the numbers. Every operator surface should have a stat
   strip or KPI row above the fold.
4. Tables before cards before charts. The default presentation is
   tabular; reach for a card only when there's a real grouping reason;
   reach for a chart only when trend is the point.
5. Validate against the principles in §1. If a screen has whitespace
   you can't explain, density-up. If a screen has color you can't
   defend, gray it out.
