package tui

import (
    "testing"
)

func TestIgnoreStaleBatches(t *testing.T) {
    m := &rootModel{}
    m.generation = 2
    if _, _ = m.Update(QueryBatch{Generation: 1, Items: []artifactSummary{{ID: "A"}}}); len(m.rows) != 0 {
        t.Fatalf("stale batch should be ignored")
    }
}

