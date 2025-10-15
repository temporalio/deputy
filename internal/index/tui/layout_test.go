package tui

import "testing"

func TestComputeLayoutTiers(t *testing.T) {
    m := &rootModel{showTree: true, showDetail: true, treeRatio: 0.25, stackRatio: 0.6}

    // Compact
    cfg := m.computeLayout(80, 30)
    if !cfg.detailsBelow { t.Fatalf("compact: expected detailsBelow") }
    if cfg.listWidth <= 0 || cfg.listHeight <= 0 { t.Fatalf("compact: list dims invalid") }
    if cfg.treeWidth > 0 && cfg.treeWidth < 10 { t.Fatalf("compact: tree too small or negative") }

    // Standard
    cfg = m.computeLayout(120, 40)
    if !cfg.detailsBelow { t.Fatalf("standard: expected detailsBelow") }
    if cfg.treeWidth < 16 { t.Fatalf("standard: expected tree width >=16 got %d", cfg.treeWidth) }
    if cfg.listWidth <= 0 { t.Fatalf("standard: list width invalid") }
    if cfg.treeHeight != cfg.listHeight { t.Fatalf("standard: treeHeight %d must equal listHeight %d", cfg.treeHeight, cfg.listHeight) }

    // Wide
    cfg = m.computeLayout(180, 50)
    if cfg.detailsBelow { t.Fatalf("wide: expected details on right (not below)") }
    if cfg.detailsWidth == 0 { t.Fatalf("wide: expected details width > 0") }
}

func TestComputeLayoutVerySmallHeight(t *testing.T) {
    m := &rootModel{showTree: true, showDetail: true, treeRatio: 0.25, stackRatio: 0.6}
    cfg := m.computeLayout(88, 12)
    if cfg.listHeight <= 0 { t.Fatalf("listHeight should remain positive, got %d", cfg.listHeight) }
    // In very short terminals details may collapse
    if cfg.detailsHeight < 0 { t.Fatalf("detailsHeight negative") }
}
