package tui

import "testing"

func TestListRenderingSelection(t *testing.T) {
    l := newArtifactList(make(chan event, 1))
    l.SetSize(80, 10)
    rows := []artifactSummary{
        {Namespace: "security", Type: "vuln", Repo: "r", ID: "CVE-1", Timestamp: "2024-10-01T00:00:00Z", Entity: "repo/x"},
        {Namespace: "security", Type: "vuln", Repo: "r", ID: "CVE-2", Timestamp: "2024-10-01T00:00:00Z", Entity: "repo/x"},
    }
    l.SetRows(rows)
    l.Focus()
    out := l.View()
    if !contains(out, "◉") {
        t.Fatalf("expected focused selection bullet in view: %s", out)
    }
    l.Blur()
    out2 := l.View()
    if !contains(out2, "◉") { // bullet still appears, style changes; keep simple check
        t.Fatalf("expected selection bullet when unfocused as well: %s", out2)
    }
}

