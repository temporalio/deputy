package tui

import "testing"

func TestFacetTreeRebuild(t *testing.T) {
    ft := newFacetTree(make(chan event, 1))
    rows := []artifactSummary{
        {Namespace: "security", Type: "vuln", Repo: "a"},
        {Namespace: "security", Type: "vuln", Repo: "a"},
        {Namespace: "security", Type: "vuln", Repo: "b"},
        {Namespace: "quality", Type: "lint", Repo: "a"},
    }
    ft.SetSize(80, 20)
    ft.Rebuild(rows)
    out := ft.View()
    if !contains(out, "security") || !contains(out, "quality") {
        t.Fatalf("expected namespaces in facet view: %s", out)
    }
    if !contains(out, "a") || !contains(out, "b") {
        t.Fatalf("expected repos in facet view: %s", out)
    }
}

func contains(s, sub string) bool { return len(s) >= len(sub) && (indexOf(s, sub) >= 0) }
func indexOf(s, sub string) int {
    for i := 0; i+len(sub) <= len(s); i++ {
        if s[i:i+len(sub)] == sub { return i }
    }
    return -1
}

