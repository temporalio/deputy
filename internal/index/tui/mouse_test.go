package tui

import (
    "testing"
    tea "github.com/charmbracelet/bubbletea/v2"
)

func TestMouseClickFocusListAndSelect(t *testing.T) {
    m := &rootModel{ width: 120, height: 30, showTree: true, showDetail: true, treeRatio: 0.2, stackRatio: 0.7 }
    // seed components to avoid zero-value panics on focus management
    m.eventCh = make(chan event, 1)
    m.filter = newFilterBar(m.eventCh)
    m.facets = newFacetTree(m.eventCh)
    m.detail = newDetailPanel()
    m.status = newStatusBar()
    m.focus = focusList
    // seed rows
    m.rows = []artifactSummary{{ID: "a"},{ID: "b"},{ID: "c"},{ID: "d"}}
    m.list.SetSize(80, 20)
    m.list.SetRows(m.rows)
    m.reflow()
    // Click somewhere in the list region: y=5 (body line), x large past tree width
    msg := tea.MouseClickMsg{X: 40, Y: 5, Button: tea.MouseLeft}
    _, cmd := m.Update(msg)
    _ = cmd
    if m.focus != focusList {
        t.Fatalf("expected focusList, got %v", m.focus)
    }
    if m.list.Cursor() < 0 || m.list.Cursor() >= len(m.rows) {
        t.Fatalf("cursor out of range: %d", m.list.Cursor())
    }
}
