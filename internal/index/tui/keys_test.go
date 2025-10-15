package tui

import "testing"

func TestAllowGlobalInFilter(t *testing.T) {
    // Letters should not be global while typing
    if allowGlobalInFilter("t") { t.Fatalf("'t' must not be global in filter") }
    if allowGlobalInFilter("d") { t.Fatalf("'d' must not be global in filter") }
    if allowGlobalInFilter("space") { t.Fatalf("'space' must not be global in filter") }
    // Navigation / overlays should be allowed
    for _, k := range []string{"tab", "shift+tab", "ctrl+left", "ctrl+right", "ctrl+up", "ctrl+down", "ctrl+l", ":", "?"} {
        if !allowGlobalInFilter(k) { t.Fatalf("%q should be global in filter", k) }
    }
}

