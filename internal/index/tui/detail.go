package tui

import (
    "encoding/json"
    "strings"
    tea "github.com/charmbracelet/bubbletea/v2"
    "github.com/charmbracelet/bubbles/v2/viewport"
    runewidth "github.com/mattn/go-runewidth"
)

type detailTab int
const (
    tabSummary detailTab = iota
    tabRels
    tabJSON
)

type detailPanelModel struct {
    vp      viewport.Model
    focused bool
    tab     detailTab

    // bound data
    item *artifactSummary
    outW int
    outH int
    compact bool
}

func newDetailPanel() detailPanelModel {
    vp := viewport.New(viewport.WithWidth(1), viewport.WithHeight(1))
    vp.FillHeight = true
    vp.SoftWrap = true
    return detailPanelModel{ vp: vp, tab: tabSummary }
}

func (m *detailPanelModel) SetSize(w, h int) { m.outW, m.outH = w, h; m.vp.SetWidth(paneInnerWidth(w)); m.vp.SetHeight(paneInnerHeight(h)); m.applyStyle() }
func (m *detailPanelModel) Focus() { m.focused = true; m.applyStyle() }
func (m *detailPanelModel) Blur()  { m.focused = false; m.applyStyle() }
func (m *detailPanelModel) SetCompact(c bool) { m.compact = c; m.applyStyle() }
func (m *detailPanelModel) applyStyle() { m.vp.Style = paneBox(m.outW, m.focused, m.compact) }

func (m *detailPanelModel) SetItem(it *artifactSummary) {
    m.item = it
    m.render()
}

func (m *detailPanelModel) Update(msg tea.Msg) tea.Cmd {
    switch msg := msg.(type) {
    case tea.KeyPressMsg:
        switch msg.String() {
        case "left", "h":
            if m.tab > 0 { m.tab-- }; m.render(); return nil
        case "right", "l":
            if m.tab < tabJSON { m.tab++ }; m.render(); return nil
        case "1": m.tab = tabSummary; m.render(); return nil
        case "2": m.tab = tabRels; m.render(); return nil
        case "3": m.tab = tabJSON; m.render(); return nil
        }
    }
    vp, cmd := m.vp.Update(msg)
    m.vp = vp
    return cmd
}

func (m *detailPanelModel) render() {
    w := m.vp.Width()
    var b strings.Builder
    // Tabs
    tabs := []string{
        pickStyle(m.tab==tabSummary, "Summary"),
        pickStyle(m.tab==tabRels, "Relationships"),
        pickStyle(m.tab==tabJSON, "JSON"),
    }
    b.WriteString(strings.Join(tabs, "  "))
    b.WriteString("\n\n")
    if m.item == nil {
        b.WriteString(styleDim.Render("No item selected"))
        m.vp.SetContent(b.String()); return
    }
    switch m.tab {
    case tabSummary:
        b.WriteString(styleHeader.Render(m.item.Namespace+" "+m.item.Type))
        b.WriteString("\n")
        b.WriteString(m.item.ID)
        b.WriteString("\n\n")
        b.WriteString(styleLabel.Render("Repository:"))
        b.WriteString(" "+m.item.Repo+"\n")
        b.WriteString(styleLabel.Render("Entity:"))
        b.WriteString(" "+m.item.Entity+"\n")
        b.WriteString(styleLabel.Render("Timestamp:"))
        b.WriteString(" "+m.item.Timestamp+"\n")
        if m.item.Severity != "" {
            b.WriteString(styleLabel.Render("Severity:"))
            b.WriteString(" "+m.item.Severity+"\n")
        }
    case tabRels:
        if len(m.item.Relationships) == 0 { b.WriteString("-\n"); break }
        for _, r := range m.item.Relationships {
            b.WriteString("◆ "+r)
            b.WriteString("\n")
        }
    case tabJSON:
        raw, _ := json.MarshalIndent(m.item.Raw, "", "  ")
        b.Write(raw)
    }
    _ = w // keep for future wrapping
    m.vp.SetContent(b.String())
}

func (m *detailPanelModel) View() string { return placeBox(m.outW, m.outH, m.vp.View()) }

// Click handles mouse clicks within the detail viewport content area
func (m *detailPanelModel) Click(x, y int) {
    if y < 0 || x < 0 { return }
    if y <= 0 { // tabs row (be tolerant at y==0)
        // Build plain labels exactly as rendered
        labels := []string{ m.tabLabel("Summary"), m.tabLabel("Relationships"), m.tabLabel("JSON") }
        start := 0
        for i, lbl := range labels {
            w := runewidth.StringWidth(lbl)
            if x >= start && x < start+w {
                switch i {
                case 0: m.tab = tabSummary
                case 1: m.tab = tabRels
                case 2: m.tab = tabJSON
                }
                m.render()
                return
            }
            start += w + 2 // account for "  " join spacing
        }
    }
}

func (m *detailPanelModel) tabLabel(name string) string {
    if (name == "Summary" && m.tab==tabSummary) || (name=="Relationships" && m.tab==tabRels) || (name=="JSON" && m.tab==tabJSON) {
        return "["+name+"]"
    }
    return name
}

func pickStyle(active bool, s string) string {
    if active { return styleTabsActive.Render("["+s+"]") }
    return styleTabsInactive.Render(s)
}
