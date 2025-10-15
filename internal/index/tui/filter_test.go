package tui

import (
    "testing"
    tea "github.com/charmbracelet/bubbletea/v2"
)

func TestFilterSubmitSendsEvent(t *testing.T) {
    ch := make(chan event, 1)
    f := newFilterBar(ch)
    f.input.SetValue("artifact_namespace == 'security'")
    cmd := f.Submit(42)
    if cmd == nil { t.Fatalf("expected non-nil cmd") }
    // Execute command as Bubble Tea would
    var m tea.Msg = cmd()
    _ = m
    select {
    case ev := <-ch:
        fs, ok := ev.(FilterSubmitted)
        if !ok { t.Fatalf("expected FilterSubmitted event, got %T", ev) }
        if fs.Generation != 42 { t.Fatalf("expected generation 42, got %d", fs.Generation) }
        if fs.Expression == "" { t.Fatalf("expected non-empty expression") }
    default:
        t.Fatalf("expected event on channel")
    }
}

