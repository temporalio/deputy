package tui

import (
    "testing"
    "time"
)

func TestBudgetDeniesAndDisablesLive(t *testing.T) {
    m := &rootModel{ liveQuery: true, liveBudgetMax: 0, eventCh: make(chan event, 1) }
    // Simulate incoming FilterSubmitted while live-query is on and budget=0
    _, _ = m.Update(FilterSubmitted{ Generation: 1, Expression: "true" })
    if m.liveQuery { t.Fatalf("expected liveQuery to be disabled when budget exceeded") }
}

func TestRemainingBudgetWindow(t *testing.T) {
    m := &rootModel{ liveBudgetMax: 2 }
    now := time.Now()
    if rem := m.remainingBudget(now); rem != 2 { t.Fatalf("expected 2 remaining, got %d", rem) }
    if ok := m.consumeBudget(now); !ok { t.Fatalf("expected first consume ok") }
    if rem := m.remainingBudget(now); rem != 1 { t.Fatalf("expected 1 remaining, got %d", rem) }
    // advance beyond window and ensure reset
    later := now.Add(61 * time.Second)
    if rem := m.remainingBudget(later); rem != 2 { t.Fatalf("expected window reset, got %d", rem) }
}

