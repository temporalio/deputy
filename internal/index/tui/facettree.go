package tui

import (
    "sort"
    "strings"
    tea "github.com/charmbracelet/bubbletea/v2"
    "github.com/charmbracelet/bubbles/v2/viewport"
)

type facetTreeModel struct {
    vp      viewport.Model
    focused bool
    eventCh chan event
    outW    int
    outH    int
    compact bool

    // computed tree counts
    tree map[string]map[string]map[string]int // ns -> type -> repo -> count
    order []string
}

func newFacetTree(ch chan event) facetTreeModel {
    vp := viewport.New(viewport.WithWidth(1), viewport.WithHeight(1))
    vp.FillHeight = true
    return facetTreeModel{ vp: vp, eventCh: ch }
}

func (m *facetTreeModel) SetSize(w, h int) {
    m.outW, m.outH = w, h
    m.vp.SetWidth(w)
    m.vp.SetHeight(h)
    m.applyStyle()
}
func (m *facetTreeModel) Focus() { m.focused = true; m.applyStyle() }
func (m *facetTreeModel) Blur()  { m.focused = false; m.applyStyle() }
func (m *facetTreeModel) SetCompact(c bool) { m.compact = c; m.applyStyle() }

func (m *facetTreeModel) applyStyle() {
    m.vp.Style = paneBox(m.outW, m.focused, m.compact)
}

func (m *facetTreeModel) Update(msg tea.Msg) tea.Cmd {
    vp, cmd := m.vp.Update(msg)
    m.vp = vp
    return cmd
}

func (m *facetTreeModel) Rebuild(arts []artifactSummary) {
    tree := map[string]map[string]map[string]int{}
    for _, a := range arts {
        ns := a.Namespace
        ty := a.Type
        repo := a.Repo
        if repo == "" { repo = "(unknown)" }
        if tree[ns] == nil { tree[ns] = map[string]map[string]int{} }
        if tree[ns][ty] == nil { tree[ns][ty] = map[string]int{} }
        tree[ns][ty][repo]++
    }
    m.tree = tree

    // render
    var lines []string
    lines = append(lines, styleHeader.Render("FACETS"))
    nsKeys := keys(tree)
    sort.Strings(nsKeys)
    for _, ns := range nsKeys {
        lines = append(lines, " "+ns)
        tyMap := tree[ns]
        tyKeys := keys(tyMap)
        sort.Strings(tyKeys)
        for _, ty := range tyKeys {
            lines = append(lines, "   "+ty)
            rpMap := tyMap[ty]
            rpKeys := keys(rpMap)
            sort.Strings(rpKeys)
            for _, rp := range rpKeys {
                lines = append(lines, "     "+rp+styleDim.Render(" ("+itoa(rpMap[rp])+")"))
            }
        }
    }
    m.vp.SetContent(strings.Join(lines, "\n"))
}

func (m *facetTreeModel) View() string { return placeBox(m.outW, m.outH, m.vp.View()) }

// helpers
func keys[K comparable, V any](m map[K]V) []K {
    k := make([]K, 0, len(m))
    for key := range m { k = append(k, key) }
    return k
}

// For integration, provide a simple selection emit in future.

// artifactSummary is defined in root.go.
