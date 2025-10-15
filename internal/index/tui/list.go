package tui

import (
    "strings"
    tea "github.com/charmbracelet/bubbletea/v2"
    "github.com/charmbracelet/bubbles/v2/viewport"
    "github.com/picatz/deputy/internal/index/tui/text"
)

type artifactListModel struct {
    vp      viewport.Model
    focused bool
    eventCh chan event

    rows    []artifactSummary
    cursor  int
    outW    int
    outH    int
    dense   bool
    compact bool
}

func newArtifactList(ch chan event) artifactListModel {
    vp := viewport.New(viewport.WithWidth(1), viewport.WithHeight(1))
    vp.FillHeight = true
    return artifactListModel{ vp: vp, eventCh: ch }
}

func (m *artifactListModel) SetSize(w, h int) {
    m.outW, m.outH = w, h
    m.vp.SetWidth(w)
    m.vp.SetHeight(h)
    m.applyStyle()
}
func (m *artifactListModel) Focus() { m.focused = true; m.applyStyle() }
func (m *artifactListModel) Blur()  { m.focused = false; m.applyStyle() }
func (m *artifactListModel) applyStyle() { m.vp.Style = paneBox(m.outW, m.focused, m.compact) }
func (m *artifactListModel) SetDense(d bool) { m.dense = d; m.render() }
func (m *artifactListModel) SetCompact(c bool) { m.compact = c; m.applyStyle() }

func (m *artifactListModel) SetRows(rows []artifactSummary) {
    m.rows = rows
    if m.cursor >= len(m.rows) {
        m.cursor = max(0, len(m.rows)-1)
    }
    m.render()
}

func (m *artifactListModel) MoveCursor(delta int) {
    if len(m.rows) == 0 { return }
    m.cursor = clamp(m.cursor+delta, 0, len(m.rows)-1)
    m.render()
}

func (m *artifactListModel) JumpCursor(pos int) {
    if len(m.rows) == 0 { return }
    m.cursor = clamp(pos, 0, len(m.rows)-1)
    m.render()
}

func (m *artifactListModel) render() {
    w := max(20, m.vp.Width())
    nsW, tyW, rpW, arW := computeListWidths(w)

    var b strings.Builder
    // reserve 1 char for alignment with bullet in rows
    b.WriteString(" ")
    b.WriteString(styleListHeader.Render(
        text.PadEnd("NAMESPACE", nsW) + " " +
        text.PadEnd("TYPE", tyW) + " " +
        text.PadEnd("REPOSITORY", rpW) + " " +
        text.PadEnd("ARTIFACT", arW),
    ))
    b.WriteString("\n")
    for i, r := range m.rows {
        bullet := "○"
        rowStyle := styleListRow
        if i == m.cursor {
            if m.focused { rowStyle = styleListSel; bullet = "◉" } else { rowStyle = styleListSelUnf; bullet = "◉" }
        }
        b.WriteString(rowStyle.Render(
            bullet + " " +
            text.PadEnd(text.TruncateEnd(r.Namespace, nsW), nsW) + " " +
            text.PadEnd(text.TruncateEnd(r.Type, tyW), tyW) + " " +
            text.PadEnd(text.TruncateEnd(r.Repo, rpW), rpW) + " " +
            text.PadEnd(text.TruncateMiddle(r.ID, arW), arW),
        ))
        b.WriteString("\n")
        if !m.dense {
            b.WriteString(
                "    " + styleListMeta.Render(r.Timestamp) + "  " +
                styleListMeta.Render(sevBadge(r.Severity)) + "  " +
                styleListMeta.Render(r.Entity),
            )
            b.WriteString("\n")
        }
    }
    m.vp.SetContent(b.String())
    m.ensureCursorVisible()
}

func (m *artifactListModel) ensureCursorVisible() {
    // compute approximate line; header (1) + either 1 or 2 lines per item
    per := 2
    if m.dense { per = 1 }
    line := 1 + m.cursor*per
    if line < m.vp.YOffset {
        m.vp.SetYOffset(max(0, line-1))
    }
    if line >= m.vp.YOffset+m.vp.Height() {
        m.vp.SetYOffset(max(0, line-m.vp.Height()+1))
    }
}

func (m *artifactListModel) View() string { return placeBox(m.outW, m.outH, m.vp.View()) }

func (m *artifactListModel) Update(msg tea.Msg) tea.Cmd {
    switch msg := msg.(type) {
    case tea.KeyPressMsg:
        switch msg.String() {
        case "up", "k":
            m.MoveCursor(-1)
            return nil
        case "down", "j":
            m.MoveCursor(1)
            return nil
        case "pgup", "b":
            m.MoveCursor(-m.vp.Height())
            return nil
        case "pgdown", "f", "space":
            m.MoveCursor(m.vp.Height())
            return nil
        case "home", "g":
            m.JumpCursor(0)
            return nil
        case "end", "G":
            m.JumpCursor(len(m.rows)-1)
            return nil
        }
    }
    vp, cmd := m.vp.Update(msg)
    m.vp = vp
    return cmd
}

func (m *artifactListModel) Cursor() int { return m.cursor }

// computeListWidths allocates display widths for columns within inner width w.
// Budget accounts for 2 chars (bullet+space) and 3 single-space separators.
func computeListWidths(w int) (nsW, tyW, rpW, arW int) {
    if w < 20 { return 8, 8, 8, max(4, w-2-3-8-8-8) }
    const bulletW = 2
    const seps = 3
    budget := w - bulletW - seps
    if budget < 16 { budget = 16 }
    // Initial proportional split
    nsW = clamp(budget/8, 6, 14)
    tyW = clamp(budget/8, 6, 14)
    rpW = clamp(budget/3, 10, budget-nsW-tyW-8)
    if rpW < 10 { rpW = 10 }
    arW = budget - nsW - tyW - rpW
    if arW < 8 {
        deficit := 8 - arW
        if rpW-deficit >= 10 { rpW -= deficit; arW = 8 } else { arW = max(4, arW) }
    }
    return
}

func sevBadge(sev string) string {
    if sev == "" { return "" }
    s := strings.ToUpper(sev)
    label := "["+s+"]"
    switch s {
    case "CRITICAL":
        return styleError.Render("■")+" "+label
    case "HIGH":
        return styleError.Render("■")+" "+label
    case "MEDIUM":
        return styleWarn.Render("■")+" "+label
    case "LOW":
        return styleGood.Render("■")+" "+label
    default:
        return label
    }
}
