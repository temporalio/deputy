package tui

import (
    "context"
    "errors"
    "fmt"
    "sort"
    "strings"
    "time"

    tea "github.com/charmbracelet/bubbletea/v2"
    lipgloss "github.com/charmbracelet/lipgloss/v2"

    "github.com/picatz/deputy/internal/index"
)

// Public entrypoint
func Run(ctx context.Context, idx *index.Index) error {
    if idx == nil {
        return errors.New("tui: index cannot be nil")
    }
    if ctx == nil { ctx = context.Background() }
    m := newRoot(ctx, idx)
    p := tea.NewProgram(m, tea.WithContext(ctx), tea.WithMouseCellMotion(), tea.WithAltScreen())
    _, err := p.Run()
    return err
}

// Focusable panes
type focusArea int
const (
    focusFilter focusArea = iota
    focusTree
    focusList
    focusDetail
)

type rootModel struct {
    // env
    ctx  context.Context
    idx  *index.Index
    width, height int

    // event bus
    eventCh chan event

    // state
    generation uint64
    liveQuery  bool
    lastErr    error
    queryStart time.Time
    queryLatency time.Duration
    // live query budget per minute
    liveBudgetMax int
    liveBudgetWin []time.Time

    // layout state
    showTree   bool
    showDetail bool
    treeRatio  float64 // 0.15-0.45
    stackRatio float64 // list height ratio when stacked 0.3-0.9
    focus      focusArea

    // data
    rows      []artifactSummary
    total     int

    // components
    filter filterBarModel
    facets facetTreeModel
    list   artifactListModel
    detail detailPanelModel
    status statusBarModel
    overlays overlayManager
}

// artifactSummary is a view-optimized lightweight representation
type artifactSummary struct {
    Namespace string
    Type      string
    ID        string
    Repo      string
    Timestamp string
    Severity  string
    Entity    string
    Relationships []string
    Raw       index.Artifact
}

func newRoot(ctx context.Context, idx *index.Index) *rootModel {
    ch := make(chan event, 64)
    m := &rootModel{
        ctx: ctx,
        idx: idx,
        eventCh: ch,
        showTree: true,
        showDetail: true,
        treeRatio: 0.25,
        stackRatio: 0.6,
        focus: focusList,
        filter: newFilterBar(ch),
        facets: newFacetTree(ch),
        list:   newArtifactList(ch),
        detail: newDetailPanel(),
        status: newStatusBar(),
    }
    m.liveBudgetMax = 20
    return m
}

func (m *rootModel) Init() tea.Cmd {
    m.liveQuery = false
    m.generation++
    // Listen to events and kick off initial query
    return tea.Batch(m.listenEvents(), m.runQuery("true", m.generation))
}

func (m *rootModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
    switch msg := msg.(type) {
    case tea.MouseClickMsg:
        return m, m.handleMouseClick(msg.Mouse())
    case tea.MouseWheelMsg:
        // Route wheel to the appropriate viewport (tree/list/detail)
        bodyH := max(1, m.height-2)
        cfg := m.computeLayout(m.width, bodyH)
        yRel := msg.Y - 1
        if msg.Y <= 0 || msg.Y >= m.height-1 { return m, nil }
        if cfg.detailsBelow {
            if m.showDetail && yRel >= cfg.listHeight { // bottom pane
                vp, cmd := m.detail.vp.Update(msg)
                m.detail.vp = vp
                return m, cmd
            }
            if m.showTree && msg.X < cfg.treeWidth {
                vp, cmd := m.facets.vp.Update(msg)
                m.facets.vp = vp
                return m, cmd
            }
            vp, cmd := m.list.vp.Update(msg)
            m.list.vp = vp
            return m, cmd
        }
        // side-by-side detail on the right
        pos := 0
        if m.showTree && cfg.treeWidth > 0 {
            if msg.X < cfg.treeWidth { vp, cmd := m.facets.vp.Update(msg); m.facets.vp = vp; return m, cmd }
            pos += cfg.treeWidth + paneGutter
        }
        if msg.X >= pos && msg.X < pos+cfg.listWidth {
            vp, cmd := m.list.vp.Update(msg)
            m.list.vp = vp
            return m, cmd
        }
        // otherwise detail
        vp, cmd := m.detail.vp.Update(msg)
        m.detail.vp = vp
        return m, cmd
    case tea.WindowSizeMsg:
        m.width, m.height = msg.Width, msg.Height
        m.reflow()
        return m, nil

    case tea.KeyPressMsg:
        // Overlays take precedence
        if m.overlays.Any() {
            if top := m.overlays.Top(); top != nil && top.HandleKey(msg) { m.overlays.Pop(); return m, nil }
            return m, nil
        }

        // If typing in filter, only allow a minimal set of global bindings to avoid collisions
        if m.focus == focusFilter {
            ks := msg.String()
            if allowGlobalInFilter(ks) {
                switch ks {
                case "ctrl+c", "q":
                    return m, tea.Quit
                case "tab":
                    m.cycleFocus(1); return m, nil
                case "shift+tab":
                    m.cycleFocus(-1); return m, nil
                case "ctrl+left":
                    if m.showTree { m.treeRatio = clampFloat(m.treeRatio-0.03, 0.15, 0.45); m.reflow() }
                    return m, nil
                case "ctrl+right":
                    if m.showTree { m.treeRatio = clampFloat(m.treeRatio+0.03, 0.15, 0.45); m.reflow() }
                    return m, nil
                case "ctrl+up":
                    if m.showDetail { m.stackRatio = clampFloat(m.stackRatio+0.03, 0.3, 0.9); m.reflow() }
                    return m, nil
                case "ctrl+down":
                    if m.showDetail { m.stackRatio = clampFloat(m.stackRatio-0.03, 0.3, 0.9); m.reflow() }
                    return m, nil
                case "ctrl+l":
                    m.focus = focusList; m.updateFocus(); return m, nil
                case "?":
                    m.overlays.Push(helpOverlay{}); return m, nil
                case ":":
                    m.overlays.Push(newPalette(m.eventCh)); return m, nil
                }
            }
            // Otherwise, pass through to filter input without interpreting letters like 't', 'd', etc.
            cmd := m.filter.Update(msg, m.generation)
            return m, tea.Batch(cmd, m.listenEvents())
        }

        // Global shortcuts (when not typing in filter)
        switch msg.String() {
        case "ctrl+c", "q":
            return m, tea.Quit
        case "!":
            m.overlays.Push(newDiagOverlay(m)); return m, nil
        case "/":
            m.focus = focusFilter; m.updateFocus(); return m, nil
        case "tab":
            m.cycleFocus(1); return m, nil
        case "shift+tab":
            m.cycleFocus(-1); return m, nil
        case "ctrl+left":
            if m.showTree { m.treeRatio = clampFloat(m.treeRatio-0.03, 0.15, 0.45); m.reflow() }
            return m, nil
        case "ctrl+right":
            if m.showTree { m.treeRatio = clampFloat(m.treeRatio+0.03, 0.15, 0.45); m.reflow() }
            return m, nil
        case "ctrl+up":
            if m.showDetail { m.stackRatio = clampFloat(m.stackRatio+0.03, 0.3, 0.9); m.reflow() }
            return m, nil
        case "ctrl+down":
            if m.showDetail { m.stackRatio = clampFloat(m.stackRatio-0.03, 0.3, 0.9); m.reflow() }
            return m, nil
        case "ctrl+l":
            m.focus = focusList; m.updateFocus(); return m, nil
        case "?":
            m.overlays.Push(helpOverlay{}); return m, nil
        case ":":
            m.overlays.Push(newPalette(m.eventCh)); return m, nil
        case "v":
            cmd := m.filter.ToggleLive(); return m, tea.Batch(cmd, m.listenEvents())
        case "t":
            // toggle tree
            m.showTree = !m.showTree; if m.focus==focusTree && !m.showTree { m.focus = focusList }; m.reflow(); return m, nil
        case "d":
            m.showDetail = !m.showDetail; if m.focus==focusDetail && !m.showDetail { m.focus = focusList }; m.reflow(); return m, nil
        case "space":
            if i := m.list.Cursor(); i >=0 && i < len(m.rows) { m.overlays.Push(previewOverlay{ art: m.rows[i].Raw }) }
            return m, nil
        }

        // Delegate to focused component
        switch m.focus {
        case focusFilter:
            cmd := m.filter.Update(msg, m.generation)
            return m, tea.Batch(cmd, m.listenEvents())
        case focusTree:
            cmd := m.facets.Update(msg); return m, cmd
        case focusList:
            cmd := m.list.Update(msg)
            // Update detail pane on movement
            sel := m.list.Cursor()
            if sel >=0 && sel < len(m.rows) { m.detail.SetItem(&m.rows[sel]) }
            return m, cmd
        case focusDetail:
            cmd := m.detail.Update(msg); return m, cmd
        }

    case event:
        // All events are typed via sealed interface
        switch ev := msg.(type) {
        case FilterSubmitted:
            expr := ev.Expression
            if strings.TrimSpace(expr) == "" { expr = "true" }
            // Budget gate for live queries
            if m.liveQuery {
                if !m.consumeBudget(time.Now()) {
                    m.lastErr = fmt.Errorf("live query budget exceeded")
                    m.liveQuery = false
                    return m, m.listenEvents()
                }
            }
            m.generation++
            m.rows = nil
            m.total = 0
            m.list.SetRows(nil)
            m.facets.Rebuild(nil)
            return m, tea.Batch(m.runQuery(expr, m.generation), m.listenEvents())
        case FilterFailed:
            if ev.Generation == m.generation {
                m.lastErr = ev.Err
            }
            return m, m.listenEvents()
        case LiveQueryToggled:
            m.liveQuery = ev.On
            return m, m.listenEvents()
        case LiveBudgetSet:
            if ev.MaxPerMin >= 0 { m.liveBudgetMax = ev.MaxPerMin; m.liveBudgetWin = nil }
            return m, m.listenEvents()
        case QueryBatch:
            if ev.Generation != m.generation { return m, m.listenEvents() }
            // Append rows
            m.rows = append(m.rows, ev.Items...)
            m.total = len(m.rows)
            m.facets.Rebuild(m.rows)
            m.list.SetRows(m.rows)
            // Update detail selection if empty
            sel := m.list.Cursor(); if sel >=0 && sel < len(m.rows) { m.detail.SetItem(&m.rows[sel]) }
            return m, m.listenEvents()
        case QueryCompleted:
            if ev.Generation == m.generation {
                if ev.LatencyMs > 0 { m.queryLatency = time.Duration(ev.LatencyMs) * time.Millisecond }
            }
            return m, m.listenEvents()
        case DiagnosticsRequested:
            m.overlays.Push(newDiagOverlay(m));
            return m, m.listenEvents()
        }
    }
    return m, nil
}

// handleMouse processes mouse input to focus panes and perform basic actions
func (m *rootModel) handleMouseClick(mouse tea.Mouse) tea.Cmd {
    // Y=0 is filter line; last line is status bar
    if mouse.Y <= 0 {
        m.focus = focusFilter
        m.updateFocus()
        // best-effort cursor placement after label "Filter (CEL)  " (14)
        // and account for box padding already removed
        cur := clamp(mouse.X-14, 0, len([]rune(m.filter.input.Value())))
        m.filter.input.SetCursor(cur)
        return nil
    }
    if mouse.Y >= m.height-1 {
        // status bar: no-op for now
        return nil
    }

    bodyH := max(1, m.height-2)
    cfg := m.computeLayout(m.width, bodyH)
    yRel := mouse.Y - 1
    x := mouse.X

    // details below?
    if cfg.detailsBelow && m.showDetail && yRel >= cfg.listHeight {
        m.focus = focusDetail
        m.updateFocus()
        // Click within detail: compute relative coordinates for tabs
        topChrome := 0
        if !(m.width < 90 || m.height < 22) { topChrome = paneBorderW + paneVPad }
        yd := yRel - cfg.listHeight - paneGutter - topChrome
        xd := x - (paneBorderW + paneHPad)
        m.detail.Click(xd, yd)
        return nil
    }

    // top row
    if m.showTree && x < cfg.treeWidth {
        m.focus = focusTree
        m.updateFocus()
        return nil
    }
    // list/detail area (side-by-side)
    if !cfg.detailsBelow && m.showDetail {
        pos := 0
        if m.showTree && cfg.treeWidth > 0 {
            if x < cfg.treeWidth { m.focus = focusTree; m.updateFocus(); return nil }
            pos += cfg.treeWidth + paneGutter
        }
        if x >= pos && x < pos+cfg.listWidth {
            m.focus = focusList
            m.updateFocus()
            // map click to list row as before
        } else if x >= pos+cfg.listWidth+paneGutter {
            m.focus = focusDetail
            m.updateFocus()
            topChrome := 0
            if !(m.width < 90 || m.height < 22) { topChrome = paneBorderW + paneVPad }
            xd := x - (pos+cfg.listWidth+paneGutter) - (paneBorderW + paneHPad)
            yd := yRel - topChrome
            m.detail.Click(xd, yd)
            return nil
        }
    }
    // default: list area
    m.focus = focusList
    m.updateFocus()
    // try to map click to list row
    // subtract list pane top chrome (border/padding) if present
    compact := m.width < 90 || m.height < 22
    topChrome := 0
    if !compact { topChrome = paneBorderW + paneVPad }
    yList := yRel - topChrome
    if yList < 0 { yList = 0 }
    // header line is first; lines per item depends on density
    per := 2
    if m.width < 90 || m.height < 22 { per = 1 }
    contentLine := m.list.vp.YOffset + yList
    idx := 0
    if contentLine > 1 {
        idx = (contentLine - 1) / per
    }
    if idx >= len(m.rows) { idx = len(m.rows)-1 }
    if idx < 0 { idx = 0 }
    if len(m.rows) > 0 {
        m.list.JumpCursor(idx)
        m.detail.SetItem(&m.rows[idx])
    }
    return nil
}

func (m *rootModel) View() string {
    if m.overlays.Any() {
        // Overlay view only; keep it simple for now
        top := m.overlays.Top()
        return centerIn(m.width, m.height, top.View(m.width-4, m.height-4))
    }

    var b strings.Builder
    // Filter bar (fixed width line)
    lineW := lipgloss.NewStyle().Width(m.width)
    b.WriteString(lineW.Render(m.filter.View(m.total, m.total, m.queryLatency)))
    b.WriteString("\n")

    // Avoid extra lines for errors; show them in status bar instead.

    // Layout panes
    // Reserve exactly 2 lines: 1 for filter bar, 1 for status bar
    bodyH := max(1, m.height-2)
    cfg := m.computeLayout(m.width, bodyH)
    lefts := []string{}
    if m.showTree && cfg.treeWidth>0 {
        m.facets.SetSize(cfg.treeWidth, cfg.treeHeight)
        lefts = append(lefts, m.facets.View())
    }
    m.list.SetSize(cfg.listWidth, cfg.listHeight)
    lefts = append(lefts, m.list.View())

    var body string
    if cfg.detailsBelow {
        var top string
        if len(lefts) == 2 {
            top = lipgloss.JoinHorizontal(lipgloss.Top, lefts[0], hSpacer(paneGutter), lefts[1])
        } else if len(lefts) == 1 {
            top = lefts[0]
        }
        if m.showDetail && cfg.detailsHeight>0 {
            m.detail.SetSize(cfg.detailsWidth, cfg.detailsHeight)
            bot := m.detail.View()
            // No extra spacer; borders already separate the panes
            body = lipgloss.JoinVertical(lipgloss.Left, top, bot)
        } else {
            body = top
        }
    } else {
        rights := lefts
        if m.showDetail && cfg.detailsWidth>0 {
            m.detail.SetSize(cfg.detailsWidth, cfg.detailsHeight)
            if len(lefts) == 2 {
                rights = []string{lefts[0], hSpacer(paneGutter), lefts[1], hSpacer(paneGutter), m.detail.View()}
            } else if len(lefts) == 1 {
                rights = []string{lefts[0], hSpacer(paneGutter), m.detail.View()}
            }
        }
        body = lipgloss.JoinHorizontal(lipgloss.Top, rights...)
    }

    // Ensure body fully covers its box to prevent stale cells when resizing
    b.WriteString(placeBox(m.width, bodyH, body))
    
    m.status.Set(m.total, m.total, m.queryLatency)
    // update budget status
    rem := m.remainingBudget(time.Now())
    m.status.SetBudget(m.liveBudgetMax, rem, m.liveQuery)
    b.WriteString("\n")
    b.WriteString(lineW.Render(m.status.View()))
    return b.String()
}

// Event bus listener returns one event per command; re-issue after handling
func (m *rootModel) listenEvents() tea.Cmd {
    return func() tea.Msg {
        ev, ok := <-m.eventCh
        if !ok { return nil }
        return ev
    }
}

// runQuery compiles and streams artifacts in batches into the event channel
func (m *rootModel) runQuery(expr string, gen uint64) tea.Cmd {
    ctx := m.ctx
    idx := m.idx
    ch := m.eventCh
    return func() tea.Msg {
        start := time.Now()
        compiled, err := idx.Compile(expr, nil)
        if err != nil {
            ch <- FilterFailed{ Generation: gen, Err: err }
            return nil
        }
        it, err := idx.Query(ctx, compiled)
        if err != nil {
            ch <- FilterFailed{ Generation: gen, Err: err }
            return nil
        }
        batch := make([]artifactSummary, 0, 250)
        for art, err := range it {
            if err != nil { continue }
            batch = append(batch, summarize(art))
            if len(batch) >= 250 {
                ch <- QueryBatch{ Generation: gen, Items: batch }
                batch = make([]artifactSummary, 0, 250)
            }
        }
        if len(batch) > 0 { ch <- QueryBatch{ Generation: gen, Items: batch } }
        lat := time.Since(start)
        ch <- QueryCompleted{ Generation: gen, LatencyMs: lat.Milliseconds() }
        return nil
    }
}

// live-query budget helpers
func (m *rootModel) pruneBudget(now time.Time) {
    cutoff := now.Add(-1 * time.Minute)
    i := 0
    for ; i < len(m.liveBudgetWin); i++ {
        if m.liveBudgetWin[i].After(cutoff) { break }
    }
    if i > 0 { m.liveBudgetWin = append([]time.Time{}, m.liveBudgetWin[i:]...) }
}

func (m *rootModel) remainingBudget(now time.Time) int {
    if m.liveBudgetMax <= 0 { return 0 }
    m.pruneBudget(now)
    used := len(m.liveBudgetWin)
    rem := m.liveBudgetMax - used
    if rem < 0 { rem = 0 }
    return rem
}

func (m *rootModel) consumeBudget(now time.Time) bool {
    if m.liveBudgetMax <= 0 { return false }
    if m.remainingBudget(now) <= 0 { return false }
    m.liveBudgetWin = append(m.liveBudgetWin, now)
    return true
}

// summarize maps raw artifact to summary for rendering
func summarize(art index.Artifact) artifactSummary {
    repo := artifactRepository(art)
    sev := ""
    if v, ok := art.Dimensions["severity"]; ok { sev = v }
    // relationships to string for quick view
    rels := make([]string, 0, len(art.Relationships))
    for _, r := range art.Relationships {
        if r.Type == "" && r.Target == "" { continue }
        part := r.Type+" ▶ "+r.Target
        if len(r.Metadata) > 0 {
            // stable ordering
            kv := make([]string, 0, len(r.Metadata))
            for k, v := range r.Metadata { kv = append(kv, fmt.Sprintf("%s=%v", k, v)) }
            sort.Strings(kv)
            part += " ["+strings.Join(kv, ", ")+"]"
        }
        rels = append(rels, part)
    }
    return artifactSummary{
        Namespace: art.Namespace,
        Type:      art.Type,
        ID:        art.ID,
        Repo:      repo,
        Timestamp: art.Timestamp.UTC().Format("2006-01-02 15:04:05Z07:00"),
        Severity:  sev,
        Entity:    art.Entity.Type+"/"+art.Entity.ID,
        Relationships: rels,
        Raw: art,
    }
}

// layout computation
type layoutCfg struct {
    treeWidth, listWidth, detailsWidth int
    treeHeight, listHeight, detailsHeight int
    detailsBelow bool
}

func (m *rootModel) computeLayout(width, height int) layoutCfg {
    cfg := layoutCfg{}
    if width < 90 {
        // Compact: stack details below, tree collapses to minimal width if shown.
        // Prefer list height; only render inline details when there's enough vertical space.
        cfg.detailsBelow = true
        cfg.treeWidth = 0
        gutterW := 0
        if m.showTree { cfg.treeWidth = 14; gutterW = paneGutter }
        cfg.listWidth = max(28, width - cfg.treeWidth - gutterW)
        cfg.treeHeight = height
        cfg.detailsWidth = width
        if height >= 22 {
            cfg.detailsHeight = clamp(int(float64(height)*(1.0-m.stackRatio)), 4, max(6, height-8))
        }
        gutterH := 0
        if cfg.detailsHeight > 0 { gutterH = paneGutter }
        cfg.listHeight = max(3, height - cfg.detailsHeight - gutterH)
        // Ensure tree and list share the same height on the top row
        if m.showTree { cfg.treeHeight = cfg.listHeight }
        return cfg
    }

    // Standard/Expanded
    if m.showTree {
        cfg.treeWidth = clamp(int(float64(width)*m.treeRatio), 16, max(16, width/3))
    }
    cfg.treeHeight = height
    cfg.listWidth = width - cfg.treeWidth

    if width > 140 {
        // Details right if space
        if m.showDetail {
            detailWidth := clamp(width/3, 28, width/2)
            cfg.detailsWidth = detailWidth
            cfg.detailsHeight = height
            cfg.detailsBelow = false
            gutters := 0
            if m.showTree { gutters += paneGutter }
            gutters += paneGutter // between list and detail
            cfg.listWidth = width - cfg.treeWidth - cfg.detailsWidth - gutters
            cfg.listHeight = height
            return cfg
        }
        cfg.listHeight = height
        return cfg
    }

    // Stack details
    cfg.detailsBelow = true
    cfg.detailsWidth = width
    if m.showDetail {
        // If height is tight, collapse inline details entirely
        if height < 22 {
            cfg.detailsHeight = 0
        } else {
            cfg.detailsHeight = clamp(int(float64(height)*(1.0-m.stackRatio)), 4, max(6, height-6))
        }
    }
    gutterH := 0
    if cfg.detailsHeight > 0 { gutterH = paneGutter }
    cfg.listHeight = max(3, height - cfg.detailsHeight - gutterH)
    // Keep tree height equal to list height when stacking details below
    if m.showTree { cfg.treeHeight = cfg.listHeight }
    return cfg
}

func (m *rootModel) reflow() {
    // Update component widths based on layout
    bodyH := max(1, m.height-2)
    cfg := m.computeLayout(m.width, bodyH)
    m.filter.SetWidth(m.width)
    compact := m.width < 90 || m.height < 22
    if m.showTree { m.facets.SetSize(cfg.treeWidth, cfg.treeHeight); m.facets.SetCompact(compact) }
    m.list.SetSize(cfg.listWidth, cfg.listHeight)
    m.list.SetDense(compact)
    m.list.SetCompact(compact)
    if m.showDetail { m.detail.SetSize(cfg.detailsWidth, cfg.detailsHeight); m.detail.SetCompact(compact) }
    m.updateFocus()
}

func (m *rootModel) cycleFocus(delta int) {
    areas := m.activeAreas()
    if len(areas) == 0 { return }
    idx := 0
    for i, a := range areas { if a == m.focus { idx = i; break } }
    idx = (idx + delta + len(areas)) % len(areas)
    m.focus = areas[idx]
    m.updateFocus()
}

func (m *rootModel) activeAreas() []focusArea {
    areas := []focusArea{focusFilter}
    if m.showTree { areas = append(areas, focusTree) }
    areas = append(areas, focusList)
    if m.showDetail { areas = append(areas, focusDetail) }
    return areas
}

func (m *rootModel) updateFocus() {
    m.filter.Blur(); m.facets.Blur(); m.list.Blur(); m.detail.Blur()
    switch m.focus {
    case focusFilter: m.filter.Focus()
    case focusTree: m.facets.Focus()
    case focusList: m.list.Focus()
    case focusDetail: m.detail.Focus()
    }
}

// formatting helpers in this package

// allowGlobalInFilter returns true if a keybinding should be handled globally
// while the filter input is focused. This deliberately excludes plain letters
// like 't', 'd', and 'space' so typing isn't hijacked by global toggles.
func allowGlobalInFilter(key string) bool {
    switch key {
    case "ctrl+c", "q", "tab", "shift+tab", "ctrl+left", "ctrl+right", "ctrl+up", "ctrl+down", "ctrl+l", "?", ":":
        return true
    default:
        return false
    }
}

func clamp(v, minVal, maxVal int) int {
    if v < minVal { return minVal }
    if v > maxVal { return maxVal }
    return v
}
func clampFloat(v, minVal, maxVal float64) float64 {
    if v < minVal { return minVal }
    if v > maxVal { return maxVal }
    return v
}
func max(a, b int) int { if a>b { return a }; return b }

// artifactRepository reused from previous PoC utility
func artifactRepository(art index.Artifact) string {
    if repo, ok := art.Dimensions["repository"]; ok && repo != "" { return repo }
    if repo, ok := art.Context["repository"].(string); ok && repo != "" { return repo }
    if art.Entity.Metadata != nil {
        if repo, ok := art.Entity.Metadata["repository"].(string); ok && repo != "" { return repo }
    }
    return ""
}

// Simple helper to center overlay
func centerIn(w, h int, content string) string {
    // no-op centering by wrapping in pane; rely on overlay View sizing
    return lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center, content)
}
