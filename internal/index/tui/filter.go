package tui

import (
    "strings"
    "time"
    tea "github.com/charmbracelet/bubbletea/v2"
    "github.com/charmbracelet/bubbles/v2/textinput"
    lipgloss "github.com/charmbracelet/lipgloss/v2"
)

type filterBarModel struct {
    input      textinput.Model
    focused    bool
    live       bool
    lastSubmit time.Time
    lastExpr   string
    eventCh    chan event
    outW       int
}

func newFilterBar(ch chan event) filterBarModel {
    ti := textinput.New()
    ti.Prompt = ""
    ti.Placeholder = "artifact_namespace == 'security'"
    ti.SetValue("true")
    ti.CursorEnd()
    return filterBarModel{ input: ti, eventCh: ch }
}

func (m *filterBarModel) SetWidth(w int) { m.outW = w; m.input.SetWidth(max(16, paneInnerWidth(w))) }
func (m *filterBarModel) Focus() { m.focused = true; m.input.Focus() }
func (m *filterBarModel) Blur()  { m.focused = false; m.input.Blur() }

func (m *filterBarModel) ToggleLive() tea.Cmd {
    m.live = !m.live
    on := m.live
    ch := m.eventCh
    return func() tea.Msg { ch <- LiveQueryToggled{On: on}; return nil }
}

func (m *filterBarModel) Submit(generation uint64) tea.Cmd {
    expr := strings.TrimSpace(m.input.Value())
    if expr == "" { expr = "true" }
    m.lastSubmit = time.Now()
    m.lastExpr = expr
    ch := m.eventCh
    return func() tea.Msg { ch <- FilterSubmitted{Generation: generation, Expression: expr}; return nil }
}

func (m *filterBarModel) Update(msg tea.Msg, generation uint64) tea.Cmd {
    switch msg := msg.(type) {
    case tea.KeyPressMsg:
        switch msg.String() {
        case "enter":
            return m.Submit(generation)
        case "esc":
            m.input.SetValue(m.input.Value())
            return nil
        }
    }
    var cmd tea.Cmd
    m.input, cmd = m.input.Update(msg)
    if m.live {
        // Debounce and only emit on value change
        val := strings.TrimSpace(m.input.Value())
        return tea.Batch(cmd, tea.Tick(250*time.Millisecond, func(time.Time) tea.Msg {
            if strings.TrimSpace(val) == m.lastExpr { return nil }
            return FilterSubmitted{Generation: generation, Expression: val}
        }))
    }
    return cmd
}

func (m *filterBarModel) View(total, visible int, latency time.Duration) string {
    input := m.input.View()
    line := lipgloss.NewStyle().Width(m.outW)
    stats := styleDim.Render(
        "Total "+itoa(total)+" · Visible "+itoa(visible),
    )
    live := ""
    if m.live { live = styleGood.Render("LIVE") }
    return line.Render("Filter (CEL)  "+input+"  "+stats+"  "+live)
}

func itoa(i int) string { return fmtInt(i) }

// local minimal int->string without fmt to reduce imports in this file
func fmtInt(i int) string {
    if i == 0 { return "0" }
    neg := i < 0
    if neg { i = -i }
    buf := [20]byte{}
    bp := len(buf)
    for i>0 { bp--; buf[bp] = byte('0' + i%10); i/=10 }
    if neg { bp--; buf[bp]='-' }
    return string(buf[bp:])
}
