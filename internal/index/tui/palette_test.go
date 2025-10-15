package tui

import (
    "testing"
)

func TestPaletteSetLiveQueryEvent(t *testing.T) {
    ch := make(chan event, 1)
    p := newPalette(ch)
    p.parseAndEmit("set live-query true")
    select {
    case e := <-ch:
        if _, ok := e.(LiveQueryToggled); !ok { t.Fatalf("expected LiveQueryToggled, got %T", e) }
    default:
        t.Fatalf("no event emitted")
    }
}

func TestPaletteDiagnosticsEvent(t *testing.T) {
    ch := make(chan event, 1)
    p := newPalette(ch)
    p.parseAndEmit("diag")
    select {
    case e := <-ch:
        if _, ok := e.(DiagnosticsRequested); !ok { t.Fatalf("expected DiagnosticsRequested, got %T", e) }
    default:
        t.Fatalf("no event emitted")
    }
}
