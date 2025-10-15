package tui

import (
    "encoding/json"
    "strings"
    tea "github.com/charmbracelet/bubbletea/v2"
    "github.com/picatz/deputy/internal/index"
    "fmt"
    "time"
)

// Overlay interface and manager
type overlay interface {
    View(w, h int) string
    HandleKey(msg tea.KeyPressMsg) (handled bool)
}

type overlayManager struct{ stack []overlay }

func (o *overlayManager) Push(ov overlay) { o.stack = append(o.stack, ov) }
func (o *overlayManager) Pop() { if len(o.stack) > 0 { o.stack = o.stack[:len(o.stack)-1] } }
func (o *overlayManager) Top() overlay { if len(o.stack)==0 { return nil }; return o.stack[len(o.stack)-1] }
func (o *overlayManager) Any() bool { return len(o.stack) > 0 }

// Help overlay
type helpOverlay struct{}

func (helpOverlay) View(w, h int) string {
    lines := []string{
        styleTitle.Render("DEPUTY INDEX EXPLORER — HELP"),
        "",
        "Keyboard:",
        "  / focus filter   Enter submit   v live toggle",
        "  Tab/Shift+Tab cycle panes   Ctrl+L list",
        "  Ctrl+←/→ tree width   Ctrl+↑/↓ detail height",
        "  ↑/↓/PgUp/PgDn navigate   g/G home/end",
        "  Space quick preview   : command palette",
        "  ? help   q quit",
        "",
        styleDim.Render("Esc to close"),
    }
    content := strings.Join(lines, "\n")
    return stylePane.Width(w-4).Render(content)
}
func (helpOverlay) HandleKey(msg tea.KeyPressMsg) bool {
    s := msg.String()
    return s == "esc" || s == "enter" || s == "q" || s == "?"
}

// Quick preview overlay for an artifact
type previewOverlay struct{ art index.Artifact }

func (p previewOverlay) View(w, h int) string {
    var b strings.Builder
    b.WriteString(styleTitle.Render("QUICK PREVIEW"))
    b.WriteString("\n\n")
    b.WriteString(styleHeader.Render(p.art.Namespace+" "+p.art.Type))
    b.WriteString("\n")
    b.WriteString(p.art.ID)
    b.WriteString("\n\n")
    b.WriteString(styleLabel.Render("Entity:"))
    b.WriteString(" ")
    b.WriteString(p.art.Entity.Type+"/"+p.art.Entity.ID)
    b.WriteString("\n")
    b.WriteString(styleLabel.Render("Timestamp:"))
    b.WriteString(" ")
    b.WriteString(p.art.Timestamp.UTC().Format("2006-01-02 15:04:05Z07:00"))
    b.WriteString("\n\n")
    b.WriteString(styleLabel.Render("JSON:"))
    b.WriteString("\n")
    raw, _ := json.MarshalIndent(p.art, "", "  ")
    b.WriteString(string(raw))
    return stylePane.Width(w-4).Height(h-4).Render(b.String())
}
func (p previewOverlay) HandleKey(msg tea.KeyPressMsg) bool {
    s := msg.String()
    return s == "esc" || s == "enter" || s == "space"
}

// Diagnostics overlay to dump layout information for debugging renders
type diagOverlay struct{ root *rootModel }

func newDiagOverlay(r *rootModel) overlay { return diagOverlay{root: r} }

func (d diagOverlay) View(w, h int) string {
    if d.root == nil { return stylePane.Width(w-4).Height(h-4).Render("<no root>") }
    m := d.root
    bodyH := max(1, m.height-2)
    cfg := m.computeLayout(m.width, bodyH)
    dense := m.width < 90 || m.height < 22
    lines := []string{
        styleTitle.Render("DIAGNOSTICS"),
        "",
        styleDim.Render("terminal:"),
        fmt.Sprintf("  size: %dx%d (bodyH=%d, dense=%v)", m.width, m.height, bodyH, dense),
        styleDim.Render("layout:"),
        fmt.Sprintf("  detailsBelow=%v", cfg.detailsBelow),
        fmt.Sprintf("  tree:   %dx%d", cfg.treeWidth, cfg.treeHeight),
        fmt.Sprintf("  list:   %dx%d (cursor=%d, yOff=%d)", cfg.listWidth, cfg.listHeight, m.list.cursor, m.list.vp.YOffset),
        fmt.Sprintf("  detail: %dx%d", cfg.detailsWidth, cfg.detailsHeight),
        styleDim.Render("state:"),
        fmt.Sprintf("  showTree=%v showDetail=%v live=%v budget=%d rem=%d", m.showTree, m.showDetail, m.liveQuery, m.liveBudgetMax, m.remainingBudget(time.Now())),
        "",
        styleDim.Render("keys:"),
        "  ! diagnostics  : command palette  ? help",
        "  / filter  Tab cycle panes  Ctrl+arrows resize",
    }
    content := strings.Join(lines, "\n")
    // Keep a tight 1-character margin around the overlay
    return stylePane.Width(max(0, w-2)).Height(max(0, h-2)).Render(content)
}

func (d diagOverlay) HandleKey(msg tea.KeyPressMsg) bool {
    s := msg.String()
    return s == "esc" || s == "enter" || s == "!"
}
