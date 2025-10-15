# Index TUI Design Language

_Status: draft (rev 4)_  
_Primary audience: Deputy maintainers, platform engineers, security analysts_

## 1. Purpose & Outcomes

Deputy’s Pebble-backed index deserves a first-class console: a calm yet powerful interface where
engineers can filter, pivot, and investigate artifacts without friction. This document defines the
visual language, interaction model, and architectural boundaries for the next-generation viewer.
The TUI must feel premium—precise, deliberate, dependable—while scaling from a narrow tmux pane to
an external monitor.

### Objectives

- Deliver a responsive Ultraviolet layout that keeps filter, results, and details accessible at any width.
- Provide interaction patterns that resonate with developers and security analysts: keyboard-first,
  command palette, CEL expressions, contextual actions.
- Establish a modular Bubble Tea architecture ready for live queries, automation hooks, health metrics,
  and rigorous operational controls.

## 2. Visual Identity & Styling

### Palette

| Token             | Dark (default) | Light counterpart | Usage                                        |
|-------------------|----------------|-------------------|----------------------------------------------|
| `bg.base`         | `#1f2430`      | `#ffffff`         | Root background                              |
| `bg.surface`      | `#2b303b`      | `#f2f4f8`         | Pane surfaces, cards                          |
| `accent.primary`  | `#8fbcbb`      | `#34526f`         | Focus rings, highlights, badge fills          |
| `accent.secondary`| `#b48ead`      | `#6e4d77`         | Tree selections, tab indicators               |
| `text.high`       | `#eceff4`      | `#222a33`         | Primary text                                  |
| `text.low`        | `#a6accd`      | `#4f5b66`         | Secondary text, labels                        |
| `status.good`     | `#a3be8c`      | `#59744c`         | Healthy status indicators                     |
| `status.warn`     | `#ebcb8b`      | `#a06817`         | Warning indicators                            |
| `status.error`    | `#bf616a`      | `#802f38`         | Error states                                  |

> Light theme surfaces apply UV `shadow-sm` to retain depth. Ensure minimum contrast 4.5:1 for `text.low`.

### Borders & Padding

- Outer frames: rounded corners via `╭─╮`, `╰─╯`.
- Internal dividers: single line `│`, `─` for a refined grid; avoid double borders.
- Standard padding: horizontal 1, vertical 0 or 1 depending on density.
- Minimum pane widths: tree `≥16`, detail `≥28` to prevent collapse.

### Typography & Glyphs

- Title: uppercase accent secondary (`DEPUTY INDEX EXPLORER`).
- Section headers: spaced uppercase (`NAMESPACE`, `RELATIONSHIPS`).
- Severity badges: `■` tinted by status color.
- Selection bullets: `◉` (focused), `○` (unfocused) preceding artifact titles.
- Truncation: use middle ellipsis `⋯`; apply ANSI gradient fade for clipped cells.

## 3. Layout Strategy

Responsive tiers determined by terminal width:

### 3.1 Compact (< 90 cols)

```
╭──────────────────────────────╮
│ Filter (CEL)   [ expr     ]  │
├──────────────────────────────┤
│ Facets                      │
│ ├─ namespace/type groups    │
│ └─ per repo counts          │
├──────────────────────────────┤
│ Results (virtualized list)  │
│ └─ lightweight cards        │
├──────────────────────────────┤
│ Details (tabs collapse)     │
╰──────────────────────────────╯
```

- Tree collapses to accordion; detail pane becomes overlay triggered by `Space`/`Enter`.
- Filter bar supports optional live-query mode (spinner shown while executing).

### 3.2 Standard (90–140 cols)

```
╭───────────────────────────────────────────────────────────────╮
│ Filter (CEL)   [ expr            ]   Total 208 · Visible 208 │
├──────────────────────────────┬───────────────────────────────┤
│ Facets (≤20%)                │ Results (≥60%)                │
│ ╭──────────────────────────╮ │ ╭───────────────────────────╮ │
│ │ security (108)           │ │ │ ◉ security  sca_package  │ │
│ │   └─ github.com/... (23) │ │ │   https://github.com/... │ │
│ ╰──────────────────────────╯ │ ╰───────────────────────────╯ │
├──────────────────────────────┴───────────────────────────────┤
│ Details (full width · 40%)                                   │
│ ╭───────────────────────────────────────────────────────────╮│
│ │ Summary • Relationships • JSON                            ││
│ │ metadata key-value pairs                                  ││
│ ╰───────────────────────────────────────────────────────────╯│
╰───────────────────────────────────────────────────────────────╯
```

### 3.3 Wide (> 140 cols)

```
╭─────────────────────────────────────────────────────────────────────────────╮
│ Filter (CEL)   [ expr                                    ]  Total · Visible │
├───────────────┬──────────────────────────────────────────┬──────────────────┤
│ Facets        │ Results                                  │ Detail           │
│ (flex 0.22)   │ (flex 0.48)                              │ (flex 0.30)      │
│               │                                          │ Summary tabs …   │
└───────────────┴──────────────────────────────────────────┴──────────────────╯
```

### Adaptive Rules

- `treeRatio` (default 0.25) governs tree width; user adjustments persist.
- `stackRatio` (default 0.6) sets list height when detail stacks below.
- Live-query mode uses 250 ms debounce; cancellable contexts ensure only one query active.

## 4. Component Architecture

```
RootModel (Bubble Tea)
├─ FilterBarModel         — text input, live queries, history, autocomplete
├─ FacetTreeModel         — hierarchical counts, scoped filters
├─ ArtifactListModel      — virtualized list, severity badges, bulk selection
├─ DetailPanelModel       — tabbed summary, contextual actions
├─ StatusBarModel         — metrics, health indicator, shortcuts
└─ OverlayManager         — modals (preview, help, command palette, errors)
```

### Event Bus

- Events are typed structs implementing an unexported marker interface to guarantee compile-time safety:

  ```go
  type event interface { isEvent() }
  type FilterSubmitted struct { Generation uint64; Expression string }
  func (FilterSubmitted) isEvent() {}
  ```

- Root owns a buffered channel `eventCh chan event` with single consumer to preserve ordering. Components
  emit events via `tea.Cmd` wrapping channel sends; root dispatches synchronously to interested components.
  Backpressure handled by bounded channel + drop-on-shutdown policy.

- Supported events:
  - `FilterSubmitted`, `FilterFailed`
  - `LiveQueryToggled`
  - `FacetSelected`, `FacetCleared`
  - `ArtifactHighlighted`, `ArtifactsSelected`
  - `ArtifactAction`
  - `TogglePane`, `ResizePane`
  - `HealthStatusChanged`
  - `CompareRequested`, `BulkActionRequested`

- Metrics/audit middleware tap the event stream before dispatch.

## 5. Component Details

### 5.1 FilterBarModel

- `textinput.Model` customized with Ultraviolet styles.
- Features: autocomplete dropdown, inline diagnostics, command palette integration, history navigation.
- Live-query mode indicator (spinner + “LIVE” badge). Debounce + cancellation to avoid request storms.
- Supports macros and snippet expansion via command palette (`:snippet vuln-high`).

### 5.2 FacetTreeModel

- Renders hierarchical counts with `◉` markers for scoped nodes.
- Counts cached per node; updates via incremental merges.
- Keyboard: `↑/↓` navigate, `→` expand, `←` collapse, `Space` apply scope.
- Tooltip showing percentage of total when hovering/focused.

### 5.3 ArtifactListModel

- Two-line rows: first line summary, second line metadata (repo, ID, timestamp, severity).
- Supports multi-select (`Shift+↑/↓`, `Ctrl+A` for all) for bulk operations.
- Virtualized viewport renders only visible window; column widths precomputed per reflow.
- Contextual shortcuts: `v` quick preview, `p` pivot to repo, `E` export selection.

### 5.4 DetailPanelModel

- Tabs: `Summary`, `Relationships`, `JSON`.
- Action bar with context-sensitive actions (View CVE, Find other versions, Pivot to source/target,
  Generate report, Create ticket).
- Relationships rendered as bullet list with domain-specific icons (ASCII `◆`, `▶`).
- JSON view uses viewport with horizontal scroll and copy-to-clipboard command.

### 5.5 StatusBarModel

- Shows metrics (total, visible, query latency), shortcuts, and persistent health indicator (`●`).
- Health indicator color-coded (green/amber/red); activating opens health overlay with ingestion status.
- Displays warnings for partial results and live-query throttling.

### 5.6 OverlayManager

- Maintains LIFO stack: `Push(overlay)`, `Pop()`, `Top()`. Focus restoration guaranteed when overlays close.
- Overlay types: help, command palette, quick preview, error dialog, health detail.
- Background dim via ANSI dimming; overlays use rounded corners and consistent padding.
- Command palette grammar: `set`, `export`, `save-filter`, `load-filter`, `compare`, `bulk`, `help`.

## 6. Interaction & Keyboard Map

| Key / Gesture           | Action                                                          |
|-------------------------|-----------------------------------------------------------------|
| `/`                     | Focus filter input.                                             |
| `Enter`                 | Submit CEL expression.                                          |
| `Ctrl+R`                | Re-run current query (force refresh).                           |
| `Ctrl+L`                | Jump focus directly to list.                                    |
| `Tab / Shift+Tab`       | Cycle focus among visible panes.                                |
| `Ctrl+← / Ctrl+→`       | Resize tree width (bounded 0.15–0.45).                           |
| `Ctrl+↑ / Ctrl+↓`       | Resize detail height when stacked.                              |
| `?`                     | Help overlay.                                                   |
| `:`                     | Command palette.                                                |
| `Space`                 | Quick preview modal.                                            |
| `v`                     | Toggle live-query mode.                                         |
| `↑/↓/PgUp/PgDn`         | Navigate list.                                                   |
| `Home / End` (`g/G`)    | Jump to start/end of list.                                      |
| `Shift+↑/↓`             | Extend selection.                                                |
| `c`                     | Copy artifact JSON.                                             |
| `e`                     | Export artifact/selection.                                      |
| `Ctrl+Shift+E`          | Generate report for selection.                                  |
| `Ctrl+T`                | Create ticket for highlighted artifact (if configured).         |
| `q`                     | Quit.                                                           |

## 7. Data & Performance

- Root caches artifacts with LRU (10k items). Each entry stores summary + detail pointer.
- Streaming batches of 250 artifacts appended to per-namespace buckets; each batch tagged with `Generation` and
  applied only if `batch.Generation == activeGeneration` to prevent stale updates.
- `truncateMiddle` helper ensures consistent cell widths; detail view always shows full string.
- Pagination contract: list view exposes virtual pages (default 200 rows) and fetches further batches on
  demand; UI provides `PgDn` beyond cached range to trigger load.
- Live-query mode uses adaptive debounce (150–300 ms depending on typing cadence) with cancellation; spinner +
  message displayed while running.
- Status bar tracks query latency and queue depth; instrumentation logs metrics for benchmarking.

## 8. Text Truncation & Overflow Handling

- Trailing ellipsis for generic columns, middle ellipsis for IDs/URLs.
- ANSI fade (`[38;5;59m⋯[0m`) when content truncated.
- Detail overlays provide copy buttons for full values.
- JSON view uses horizontal scrolling; `[` and `]` adjust indent view.

## 9. Resize & Reflow Considerations

- Root handles `tea.WindowSizeMsg`, recalculates layout tree, preserves scroll offsets.
- Layout uses integer arithmetic; leftover columns distributed list > detail > tree to maintain balance.
- Optional debounce during rapid resize; ensures stable frame rate.
- Filter/status bars remain single-line, truncating metrics with ellipsis as needed.

## 10. Error Handling & Resilience

- Retries with exponential backoff (max 3) on backend errors; error states surfaced via banner + status bar.
- Timeout for queries (5s) with cancel indicator; user can abort (`Esc`).
- Index corruption detection triggers critical overlay with remediation guidance and audit log entry.
- Partial results clearly indicated (amber status, counts of received rows, `:retry` available).
- Backend unavailability shows cached results with stale badge; facets greyed out.

## 11. Security Analyst Workflows

- Bulk selection for mark-reviewed, export, ticket creation; command palette commands `bulk mark-reviewed`.
- Comparison mode `:compare <filter-a> <filter-b>` opens side-by-side delta view with color-coded changes.
- Evidence collection: `Generate Report` creates Markdown/PDF summary via CLI export.
- Ticketing integration (JIRA, etc.) via webhooks; detail panel includes action when configured.

## 12. Expression Experience & Modal System

- Autocomplete with field descriptions, macros, snippets.
- Inline diagnostics (underline + tooltip); status bar echoes errors with timestamp.
- Reference palette `Ctrl+Space` lists fields/macros; searchable via fuzzy match.
- Command palette overlays support grammar (see §15).
- Help overlay lists keyboard shortcuts, macros, sample filters.

## 13. Live Query Safety & Controls

- Disabled by default; toggled via command palette or `v`.
- Query complexity estimator warns on broad scans; requires confirmation for high-cardinality operations.
- User-configurable query budget (default 20/min); violations show red banner and temporarily disable live mode.
- Dry-run `:preview-query` displays estimated plan and row count.

## 14. Layout & Rendering Performance Principles

- Layout tree stored as flat slice; pre-order traversal calculates dimensions once per reflow.
- Dirty flags for components; only re-render when state changes.
- Viewports render visible rows only; builders recycled via `sync.Pool`.
- Batching artifact updates limits redraw frequency; render cadence capped at 60 fps via coalesced updates.
- Instrument render timings and log frames exceeding thresholds for optimization. SLIs/SLOs in §25.

## 15. Command Palette Grammar

```
set <option> <value>
export <format> [path]
save-filter <name>
load-filter <name>
compare <filter-a> <filter-b>
bulk <action> [args]
help
```

Examples: `:set live-query true`, `:export json results.json`, `:bulk mark-reviewed`.

## 16. Health Indicator

- Persistent dot `●` in status bar; color-coded to ingestion state.
- Activating indicator opens health overlay with heartbeat timestamps, error logs, retry controls.

## 17. Security Considerations

- Authentication via Deputy CLI token; secure storage in OS keychain.
- Authorization enforced server-side; UI indicates redacted content.
- Audit logging for queries, exports, bulk actions; stored locally and optionally forwarded.
- Data retention policies: cache expunged on exit, optional encrypted persistence for saved filters only.
- Sensitive fields masked by default with expand-on-demand control.

## 18. Operational & Observability Plan

- Metrics emission (optional) via local HTTP endpoint (Prometheus format) or file logs.
- Config managed through `~/.deputy/index_tui.yaml` with env overrides.
- Feature flags support gradual rollout; config includes versioning for backward compatibility.
- Health overlay pulls ingestion telemetry; manual command `:health` refreshes status.

## 19. Testing Strategy

- Unit tests with Bubble Tea `tea.Test` to simulate interactions.
- Integration tests with in-memory index and streaming scenarios.
- Performance regression suite measuring frame time with 1k/5k/10k artifacts.
- Accessibility tests: keyboard-only flows, contrast checks, optional screen reader annotations.
- Live query stress tests to ensure cancellations and budgets enforce correctly.

## 20. Implementation Roadmap

### Phase 0 – Foundation

1. Define data contracts (summaries, facets, detail payloads).
2. Implement caching layer (LRU, batching) and persistence utilities.
3. Build mock index server and synthetic data generators.
4. Establish testing harness, benchmarking framework, and audit middleware.

### Phase 1 – Core Infrastructure

- Scaffold root model, event bus, overlay manager, health pipeline.
- Create Ultraviolet layout skeleton with placeholder components.

### Phase 2 – Basic UI Functionality

- Implement FilterBar, FacetTree, ArtifactList, DetailPanel minimal feature set.
- Wire manual query execution and data rendering.
- Add error handling overlays and status messaging.

### Phase 3 – Advanced Features

- Deliver live-query mode, autocomplete, command palette grammar.
- Add contextual actions, bulk workflows, comparison view, report generation.
- Integrate ticketing hooks and export formats (CSV, JSON, PDF).

### Phase 4 – Integrations & Polish

- Finalize saved filters, automation hooks, health overlays, telemetry.
- Optimize performance using benchmarks; ensure frame time < 16 ms.
- Complete accessibility and onboarding overlays; run user acceptance tests.
- Document configuration, deployment, and operational procedures.

Rollback strategy defined per phase; progression requires all tests passing and performance targets met.

---

## 21. Data Contracts

Illustrative Go-style structs define shared expectations (approximate footprints noted):

```go
type ArtifactSummary struct {
    ID         string    // unique key, ~64B
    Namespace  string
    Type       string
    Repo       string
    Timestamp  time.Time
    Severity   string    // optional
    Generation uint64    // query generation provenance
}

type ArtifactDetail struct {
    Summary ArtifactSummary
    Entity  EntityInfo
    Data    map[string]any   // prefer concrete structs; fall back to narrow dynamic maps
    Context map[string]any   // consider json.RawMessage where passthrough is required
    Links   []Relationship
}

type EntityInfo struct {
    Type     string
    ID       string
    Metadata map[string]any
}

type Relationship struct {
    Type      string
    Direction string // out, in
    TargetID  string
    Metadata  map[string]any
}

type FacetNode struct {
    Name          string
    Path          []string
    TotalCount    int
    FilteredCount int
    Children      []FacetNode
}

type QueryBatch struct {
    Generation uint64
    Items      []ArtifactSummary
    Partial    bool
    Err        error
}

type HealthStatus struct {
    Level     string
    Message   string
    Timestamp time.Time
    Details   map[string]any
}
```

Detail payloads fetched lazily; summaries immutable within a generation. LRU eviction removes detail payloads
first, summaries last.

## 22. Query Lifecycle & Generations

- `queryGeneration` increments per submission/live-query toggle; active generation stored in root state.
- Each batch tagged with `Generation`; applied only if matching active generation, preventing stale updates.
- Cancellation triggered for new queries or user abort; backend contexts cancelled promptly.
- Error taxonomy: `TIMEOUT`, `PARTIAL`, `BACKEND_UNAVAILABLE`, `BUDGET_EXCEEDED`, `CORRUPTION`. UI handling:
  - TIMEOUT → amber banner with retry button.
  - PARTIAL → amber status, received-count indicator, `:retry` command.
  - BACKEND_UNAVAILABLE → red status, cached data shown with stale badge.
  - BUDGET_EXCEEDED → red banner, live query disabled until budget resets.
  - CORRUPTION → blocking overlay; audit log entry; prompt to run repair command.
- Comparison mode executes sequential generations, diffing results deterministically by ID.

## 23. Threat Model & Security Mitigations

| Asset                  | Threat                         | Mitigation                                         |
|------------------------|--------------------------------|-----------------------------------------------------|
| CLI auth token         | Interception, leakage          | Stored in OS keychain, never written to logs/export |
| Artifact data          | Unauthorized access            | Server-side auth, local masking of sensitive fields |
| Command palette input  | Injection, path traversal      | Whitelist verbs, validate args, escape outputs      |
| Export files           | Escape sequences, PII exposure | Sanitize ANSI, UTF-8 validation, explicit warnings  |
| Audit logs             | Sensitive data in logs         | Hash filter expressions, cap artifact IDs recorded  |

CEL sandbox enforces evaluation step/time limits and per-user budgets; compiled programs cached in LRU (256
entries) keyed by normalized expression string. Logs include compile latency and cache hit rate.

## 24. Metrics & Observability Schema

Metrics prefixed `deputy_tui_*` emitted via optional endpoint/log:

| Metric                                 | Type      | Labels                          |
|----------------------------------------|-----------|---------------------------------|
| `deputy_tui_query_latency_seconds`     | histogram | `result` (success,error), `mode`|
| `deputy_tui_render_frame_seconds`      | histogram | none                            |
| `deputy_tui_cache_entries`             | gauge     | `state` (summary,detail)        |
| `deputy_tui_event_queue_depth`         | gauge     | none                            |
| `deputy_tui_live_query_budget`         | gauge     | `state` (remaining)             |
| `deputy_tui_autocomplete_latency_ms`   | histogram | none                            |

Audit log schema (JSON lines): `timestamp`, `user`, `action`, `filter_hash`, `artifact_ids` (capped 10),
`latency_ms`, `result_count`, `status`.

## 25. Performance SLOs / SLIs

| Metric                              | Target (p95) | Notes                                        |
|-------------------------------------|--------------|----------------------------------------------|
| Time to first results (manual)      | < 1.0 s      | Local index, warm cache                      |
| Time to first results (live)        | < 1.5 s      | Debounce + backend latency inclusive         |
| Render frame duration               | < 16 ms      | Ensures 60 fps feel                          |
| Scroll latency                      | < 25 ms      | Measured via synthetic scroll tests          |
| Autocomplete latency                | < 120 ms     | From keystroke to suggestion list            |
| Live query cancellation efficacy    | 100%         | No stale batches applied                     |
| Memory footprint (10k summaries)    | < 200 MB RSS | Observed via benchmark harness               |
| Startup time                        | < 400 ms     | Cold start                                   |
| Crash-free sessions                 | > 99.5%      | Based on opt-in telemetry                     |

## 26. Accessibility Modes & Color Redundancy

- `:mode linear` renders a single-column artifact summary with explicit labels for screen readers.
- Severity badges include bracket letter `[C]`, `[H]`, `[M]`, `[L]` alongside colored square.
- `Ctrl+Alt+H` toggles high-contrast palette meeting WCAG AAA ratios.
- Screen-reader assist mode outputs linearized summaries to stdout/log on focus changes.

## 27. Testing Matrix

| Category       | Scenarios                                                                  |
|----------------|----------------------------------------------------------------------------|
| Unit           | Component updates, event dispatch, command parsing, config persistence      |
| Integration    | Query lifecycle (success/timeout/partial), streaming batches, overlay stack |
| Performance    | 1k/5k/10k artifacts streaming, scroll benchmark, live-query cadence         |
| Concurrency    | Rapid cancel/re-submit, simultaneous overlays, bulk actions                 |
| Fuzz           | `truncateMiddle`, command palette lexer, CEL input sanitization              |
| Accessibility  | Keyboard-only navigation, high-contrast mode, linear mode rendering         |
| Snapshot       | Layout tiers (<90, 120, 160, >200 cols) with deterministic fixtures         |
| Security       | Export sanitization, audit log redaction, budget enforcement, auth failures |

---

This revision incorporates performance contracts, caching strategies, error handling, security workflows,
operational concerns, explicit data contracts, and a testing matrix aligned with principal-level expectations.
The engineering team can proceed with confidence, focusing first on the foundation work outlined in Phase 0.

## 28. Go Idioms & Implementation Guidance

- **Context usage**: do not store `context.Context` on long-lived structs. Bubble Tea’s `tea.WithContext`
  supplies cancellation for commands; pass contexts explicitly to query helpers and respect `ctx.Done()`.
- **Config & options**: expose functional options (e.g., `WithCacheSize`, `WithBudget`) when constructing
  the TUI root. Persist configuration via atomic temp-file writes with version headers; ignore unknown keys.
- **Caching**: implement a minimal LRU (`Get/Put/Remove/Len`) using a trusted library or simple map+list.
  Respect the memory budget by evicting detail payloads before summaries.
- **Event package**: house event structs in a dedicated package with a sealed interface (unexported marker)
  to retain compile-time safety.
- **Overlay manager**: provide a small package exposing `Push`, `Pop`, `Top`, and `View(width,height) string`.
  Keep focus ownership in the root model to avoid hidden state.
- **Text utilities**: centralize truncation/width helpers in `internal/index/tui/text` using `runewidth`. All
  components call these helpers to keep ANSI sequences width-safe.
- **Metrics toggle**: gate Prometheus/log emission behind an optional flag (`--metrics-addr`) so default CLI
  usage stays lean.
- **Naming & docs**: avoid stutter (`tui.Model` over `tui.TUIModel`), add GoDoc comments for exported symbols,
  and keep interfaces narrow and consumer-focused.

[charmbracelet/ultraviolet]: https://github.com/charmbracelet/ultraviolet
