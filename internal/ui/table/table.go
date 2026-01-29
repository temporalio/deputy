// Package table provides a fluid, terminal-aware table formatter for CLI output.
//
// Design principles:
//   - Fluid layout that adapts to terminal width
//   - Smart truncation only when necessary
//   - Semantic value types with appropriate styling
//   - Human-friendly formatting (relative dates, styled numbers)
//   - Composable, testable, idiomatic Go
package table

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/picatz/deputy/internal/ui"
	"golang.org/x/term"
)

// Layout constants
const (
	DefaultWidth  = 120 // Fallback when terminal width unknown
	MinWidth      = 60  // Minimum usable width
	ColumnGap     = 2   // Space between columns
	MinColWidth   = 4   // Absolute minimum for any column
	Ellipsis      = "…" // Unicode ellipsis for truncation
)

// ValueType indicates how a cell value should be formatted and styled.
type ValueType int

const (
	TypeText     ValueType = iota // Plain text, truncatable
	TypeID                        // Identifier (name, key) - high priority
	TypeNumber                    // Numeric value - right aligned, styled
	TypeDate                      // Timestamp - human-friendly relative format only
	TypeDateFull                  // Timestamp - "2022-09-02 [3 years ago]" format
	TypeStatus                    // Status value - semantic coloring
	TypePath                      // File path - truncate from left if needed
	TypeDigest                    // Content digest (sha256:abc123...) - styled hash
)

// Alignment specifies text alignment within a column.
type Alignment int

const (
	AlignLeft Alignment = iota
	AlignRight
	AlignCenter
)

// Column defines a table column with layout hints and styling.
type Column struct {
	Header   string    // Column header text
	Type     ValueType // Value type for formatting/styling
	MinWidth int       // Minimum width (0 = use header length)
	MaxWidth int       // Maximum width (0 = no limit, fluid)
	Priority int       // Higher = more important, gets space first (default 0)
	Flex     float64   // Flex factor for fluid sizing (0 = fixed, 1 = normal)
	Align    Alignment // Column alignment
}

// Cell holds a value with optional pre-computed styling.
type Cell struct {
	Raw    string    // Raw value for width calculation
	Styled string    // Styled value for display (empty = use Raw)
	Type   ValueType // Override column type for this cell
}

// Table builds formatted table output with fluid layout.
type Table struct {
	columns   []Column
	rows      [][]Cell
	termWidth int
	now       time.Time // For relative date calculation (injectable for testing)
}

// New creates a new table with the given columns.
func New(columns ...Column) *Table {
	// Apply defaults
	for i := range columns {
		if columns[i].Flex == 0 && columns[i].MaxWidth == 0 {
			columns[i].Flex = 1 // Default to flexible
		}
		if columns[i].Type == TypeNumber {
			columns[i].Align = AlignRight
		}
	}
	return &Table{
		columns:   columns,
		termWidth: TerminalWidth(),
		now:       time.Now(),
	}
}

// SetWidth overrides the terminal width (useful for testing).
func (t *Table) SetWidth(w int) {
	t.termWidth = w
}

// SetNow overrides the current time (useful for testing relative dates).
func (t *Table) SetNow(now time.Time) {
	t.now = now
}

// AddRow adds a row with raw string values.
func (t *Table) AddRow(values ...string) {
	cells := make([]Cell, len(t.columns))
	for i := range t.columns {
		if i < len(values) {
			cells[i] = Cell{Raw: values[i], Type: t.columns[i].Type}
		}
	}
	t.rows = append(t.rows, cells)
}

// AddCells adds a row with pre-constructed cells (for custom styling).
func (t *Table) AddCells(cells ...Cell) {
	row := make([]Cell, len(t.columns))
	for i := range t.columns {
		if i < len(cells) {
			row[i] = cells[i]
			if row[i].Type == 0 {
				row[i].Type = t.columns[i].Type
			}
		}
	}
	t.rows = append(t.rows, row)
}

// Render writes the formatted table to w.
func (t *Table) Render(w io.Writer, showHeader bool) error {
	if len(t.columns) == 0 {
		return nil
	}

	widths := t.calculateWidths()

	if showHeader {
		t.renderHeader(w, widths)
	}

	for i := range t.rows {
		t.renderRow(w, i, widths)
	}

	return nil
}

// RowCount returns the number of data rows.
func (t *Table) RowCount() int {
	return len(t.rows)
}

// calculateWidths computes optimal column widths based on content and terminal.
func (t *Table) calculateWidths() []int {
	widths := make([]int, len(t.columns))
	minWidths := make([]int, len(t.columns))
	idealWidths := make([]int, len(t.columns))

	// First pass: calculate min and ideal widths
	for i, col := range t.columns {
		// Minimum is max of: explicit min, header length, MinColWidth
		minW := max(col.MinWidth, ansi.StringWidth(col.Header), MinColWidth)
		minWidths[i] = minW

		// Ideal is max content width (capped by MaxWidth if set)
		idealW := minW
		for _, row := range t.rows {
			if i < len(row) {
				contentW := t.estimateContentWidth(row[i], col.Type)
				idealW = max(idealW, contentW)
			}
		}
		if col.MaxWidth > 0 {
			idealW = min(idealW, col.MaxWidth)
		}
		idealWidths[i] = idealW
		widths[i] = idealW
	}

	// Calculate total and available space
	totalGaps := (len(t.columns) - 1) * ColumnGap
	available := t.termWidth - totalGaps
	if available < MinWidth {
		available = MinWidth
	}

	total := sum(widths)

	// If we fit, we're done
	if total <= available {
		return widths
	}

	// Need to shrink - use priority-based allocation
	t.shrinkToFit(widths, minWidths, available)

	return widths
}

// estimateContentWidth returns the display width of a cell after formatting.
// For date types, this accounts for the formatted output being longer than the raw input.
func (t *Table) estimateContentWidth(cell Cell, colType ValueType) int {
	raw := cell.Raw
	if raw == "" {
		return 1 // "-"
	}

	// For date types, compute the actual formatted width
	switch colType {
	case TypeDateFull:
		formatted, _ := t.formatDateFull(raw)
		return ansi.StringWidth(formatted)
	case TypeDate:
		formatted, _ := t.formatDate(raw)
		return ansi.StringWidth(formatted)
	default:
		return ansi.StringWidth(raw)
	}
}

// shrinkToFit reduces column widths to fit available space.
// Shrinks lower-priority columns first, respecting minimums.
func (t *Table) shrinkToFit(widths, minWidths []int, available int) {
	// Build priority groups (higher priority = shrink last)
	type colInfo struct {
		idx      int
		priority int
		flex     float64
	}
	cols := make([]colInfo, len(t.columns))
	for i, col := range t.columns {
		cols[i] = colInfo{i, col.Priority, col.Flex}
	}

	// Sort by priority (ascending - shrink low priority first)
	for i := 0; i < len(cols)-1; i++ {
		for j := i + 1; j < len(cols); j++ {
			if cols[i].priority > cols[j].priority {
				cols[i], cols[j] = cols[j], cols[i]
			}
		}
	}

	// Shrink columns starting with lowest priority
	for sum(widths) > available {
		shrunk := false
		for _, c := range cols {
			if widths[c.idx] > minWidths[c.idx] {
				widths[c.idx]--
				shrunk = true
				if sum(widths) <= available {
					return
				}
			}
		}
		if !shrunk {
			break // Can't shrink anymore
		}
	}
}

// renderHeader writes the styled header row.
func (t *Table) renderHeader(w io.Writer, widths []int) {
	var parts []string
	for i, col := range t.columns {
		header := Truncate(col.Header, widths[i])
		parts = append(parts, Pad(header, widths[i], col.Align))
	}
	line := strings.Join(parts, strings.Repeat(" ", ColumnGap))
	fmt.Fprintln(w, ui.StyleHeader.Render(line))
}

// renderRow writes a single data row with formatting.
func (t *Table) renderRow(w io.Writer, rowIdx int, widths []int) {
	row := t.rows[rowIdx]
	var parts []string

	for i := range t.columns {
		cell := Cell{}
		if i < len(row) {
			cell = row[i]
		}

		// Format and style the value
		display := t.formatCell(cell, widths[i])
		parts = append(parts, display)
	}

	fmt.Fprintln(w, strings.Join(parts, strings.Repeat(" ", ColumnGap)))
}

// formatCell formats a cell value with truncation, styling, and alignment.
func (t *Table) formatCell(cell Cell, width int) string {
	raw := cell.Raw
	styled := cell.Styled
	valueType := cell.Type

	// Format based on type
	switch valueType {
	case TypeDate:
		if styled == "" {
			raw, styled = t.formatDate(raw)
		}
	case TypeDateFull:
		if styled == "" {
			raw, styled = t.formatDateFull(raw)
		}
	case TypeNumber:
		if styled == "" {
			raw, styled = formatNumber(raw)
		}
	case TypeStatus:
		if styled == "" {
			styled = formatStatus(raw)
		}
	case TypeDigest:
		if styled == "" {
			raw, styled = formatDigest(raw)
		}
	}

	if styled == "" {
		styled = raw
	}

	// Truncate if needed
	rawWidth := ansi.StringWidth(raw)
	if rawWidth > width {
		// For date types, use smart truncation that preserves styling
		switch valueType {
		case TypeDateFull:
			raw, styled = t.truncateDateFull(raw, width)
		case TypeDate:
			truncated := Truncate(raw, width)
			raw = truncated
			styled = StyleDim.Render(truncated)
		default:
			truncated := Truncate(raw, width)
			raw = truncated
			styled = truncated
		}
		rawWidth = ansi.StringWidth(raw)
	}

	// Calculate padding
	padding := width - rawWidth
	if padding < 0 {
		padding = 0
	}

	// Apply alignment with styled content
	switch {
	case padding == 0:
		return styled
	default:
		return styled + strings.Repeat(" ", padding)
	}
}

// truncateDateFull smartly truncates a full date, preserving the date part when possible.
// Priority: full date+relative > date only > truncated date
func (t *Table) truncateDateFull(raw string, width int) (string, string) {
	// Try to find the date part (YYYY-MM-DD) and relative part ([...])
	// Raw format: "2024-06-15 [1 year ago]"
	bracketIdx := strings.Index(raw, " [")
	if bracketIdx == -1 {
		// No bracket, just truncate
		truncated := Truncate(raw, width)
		return truncated, StyleDim.Render(truncated)
	}

	datePart := raw[:bracketIdx]           // "2024-06-15"
	relativePart := raw[bracketIdx+2:]     // "1 year ago]"
	relativePart = strings.TrimSuffix(relativePart, "]") // "1 year ago"

	dateWidth := ansi.StringWidth(datePart)

	// If date alone fits, show just the date (styled)
	if dateWidth <= width {
		// Check if we can fit date + some of the relative time
		fullWidth := ansi.StringWidth(raw)
		if fullWidth <= width {
			// Everything fits
			styled := StyleDim.Render(datePart) + " " +
				StyleDateBracket.Render("[") +
				StyleDateRelative.Render(relativePart) +
				StyleDateBracket.Render("]")
			return raw, styled
		}
		// Just show the date
		return datePart, StyleDim.Render(datePart)
	}

	// Date doesn't fit, truncate it
	truncated := Truncate(datePart, width)
	return truncated, StyleDim.Render(truncated)
}

// formatDate converts a timestamp to human-friendly relative format.
func (t *Table) formatDate(raw string) (string, string) {
	if raw == "" || raw == "-" {
		return raw, StyleDim.Render(raw)
	}

	// Try parsing as RFC3339 or date-only
	var ts time.Time
	var err error
	for _, layout := range []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02",
	} {
		ts, err = time.Parse(layout, raw)
		if err == nil {
			break
		}
	}
	if err != nil {
		return raw, StyleDim.Render(raw)
	}

	relative := RelativeTime(ts, t.now)
	return relative, StyleDim.Render(relative)
}

// formatDateFull converts a timestamp to "2022-09-02 [3 years ago]" format.
func (t *Table) formatDateFull(raw string) (string, string) {
	if raw == "" || raw == "-" {
		return raw, StyleDim.Render(raw)
	}

	// Try parsing as RFC3339 or date-only
	var ts time.Time
	var err error
	for _, layout := range []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02",
	} {
		ts, err = time.Parse(layout, raw)
		if err == nil {
			break
		}
	}
	if err != nil {
		return raw, StyleDim.Render(raw)
	}

	// Format: "2022-09-02 [3 years ago]"
	datePart := ts.Format("2006-01-02")
	relative := RelativeTime(ts, t.now)

	// Raw is just date + relative for width calculation
	rawFull := datePart + " [" + relative + "]"

	// Styled: date is dim, brackets are very dim, relative is slightly less dim
	styled := StyleDim.Render(datePart) + " " +
		StyleDateBracket.Render("[") +
		StyleDateRelative.Render(relative) +
		StyleDateBracket.Render("]")

	return rawFull, styled
}

// formatNumber styles a numeric value based on magnitude.
func formatNumber(raw string) (string, string) {
	if raw == "" || raw == "-" {
		return raw, StyleDim.Render(raw)
	}

	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		// Try float
		if _, err := strconv.ParseFloat(raw, 64); err != nil {
			return raw, raw
		}
		return raw, raw
	}

	// Style based on magnitude
	switch {
	case n == 0:
		return raw, StyleDim.Render(raw)
	case n >= 10000:
		return raw, StyleNumberHigh.Render(raw)
	case n >= 100:
		return raw, StyleNumberMed.Render(raw)
	default:
		return raw, StyleNumber.Render(raw)
	}
}

// formatStatus styles a status value semantically.
func formatStatus(raw string) string {
	lower := strings.ToLower(raw)
	switch lower {
	case "open", "active", "success", "passed", "enabled", "stable":
		return StyleStatusGood.Render(raw)
	case "direct":
		return StyleStatusDirect.Render(raw)
	case "closed", "inactive", "disabled", "archived", "indirect":
		return StyleDim.Render(raw)
	case "merged":
		return StyleStatusMerged.Render(raw)
	case "failed", "failure", "error":
		return StyleStatusBad.Render(raw)
	case "pending", "in_progress", "queued", "prerelease":
		return StyleStatusWarn.Render(raw)
	default:
		return raw
	}
}

// formatDigest styles a content digest (e.g., "sha256:abc123...").
// The algorithm prefix is dimmed, and the hash is shown in a subtle monospace style.
func formatDigest(raw string) (string, string) {
	if raw == "" || raw == "-" {
		return raw, StyleDim.Render(raw)
	}

	// Look for algorithm:hash pattern
	if idx := strings.Index(raw, ":"); idx > 0 && idx < len(raw)-1 {
		algo := raw[:idx]   // e.g., "sha256"
		hash := raw[idx+1:] // e.g., "abc123..."

		styled := StyleDigestAlgo.Render(algo) +
			StyleDigestColon.Render(":") +
			StyleDigestHash.Render(hash)
		return raw, styled
	}

	// No colon, treat as plain hash
	return raw, StyleDigestHash.Render(raw)
}

// Styles for table formatting
var (
	StyleDim          = lipgloss.NewStyle().Foreground(lipgloss.Color("#666666"))
	StyleNumber       = lipgloss.NewStyle().Foreground(lipgloss.Color("#B0B0B0"))
	StyleNumberMed    = lipgloss.NewStyle().Foreground(lipgloss.Color("#E0E0E0"))
	StyleNumberHigh   = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700")) // Gold for high numbers
	StyleStatusGood   = lipgloss.NewStyle().Foreground(lipgloss.Color("#50C878")) // Emerald
	StyleStatusBad    = lipgloss.NewStyle().Foreground(lipgloss.Color("#E57373")) // Soft red
	StyleStatusWarn   = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFB74D")) // Amber
	StyleStatusMerged = lipgloss.NewStyle().Foreground(lipgloss.Color("#A855F7")) // Purple for merged
	StyleStatusDirect = lipgloss.NewStyle().Foreground(lipgloss.Color("#00CED1")) // Cyan/teal for direct deps
	StyleDateBracket  = lipgloss.NewStyle().Foreground(lipgloss.Color("#4A4A4A")) // Very dim brackets
	StyleDateRelative = lipgloss.NewStyle().Foreground(lipgloss.Color("#808080")) // Slightly brighter relative
	StyleDigestAlgo   = lipgloss.NewStyle().Foreground(lipgloss.Color("#6A6A6A")) // Dim algorithm prefix
	StyleDigestColon  = lipgloss.NewStyle().Foreground(lipgloss.Color("#4A4A4A")) // Very dim colon
	StyleDigestHash   = lipgloss.NewStyle().Foreground(lipgloss.Color("#8A8A8A")) // Subtle hash
)

// RelativeTime formats a timestamp as human-friendly relative time.
func RelativeTime(t time.Time, now time.Time) string {
	if t.IsZero() {
		return "-"
	}

	diff := now.Sub(t)
	if diff < 0 {
		diff = -diff
		return formatFuture(diff)
	}
	return formatPast(diff)
}

func formatPast(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		m := int(d.Minutes())
		if m == 1 {
			return "1 min ago"
		}
		return fmt.Sprintf("%d mins ago", m)
	case d < 24*time.Hour:
		h := int(d.Hours())
		if h == 1 {
			return "1 hour ago"
		}
		return fmt.Sprintf("%d hours ago", h)
	case d < 48*time.Hour:
		return "yesterday"
	case d < 7*24*time.Hour:
		days := int(d.Hours() / 24)
		return fmt.Sprintf("%d days ago", days)
	case d < 14*24*time.Hour:
		return "1 week ago"
	case d < 30*24*time.Hour:
		weeks := int(d.Hours() / 24 / 7)
		return fmt.Sprintf("%d weeks ago", weeks)
	case d < 60*24*time.Hour:
		return "1 month ago"
	case d < 365*24*time.Hour:
		months := int(d.Hours() / 24 / 30)
		return fmt.Sprintf("%d months ago", months)
	case d < 2*365*24*time.Hour:
		return "1 year ago"
	default:
		years := int(d.Hours() / 24 / 365)
		return fmt.Sprintf("%d years ago", years)
	}
}

func formatFuture(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "now"
	case d < time.Hour:
		m := int(d.Minutes())
		if m == 1 {
			return "in 1 min"
		}
		return fmt.Sprintf("in %d mins", m)
	case d < 24*time.Hour:
		h := int(d.Hours())
		if h == 1 {
			return "in 1 hour"
		}
		return fmt.Sprintf("in %d hours", h)
	default:
		days := int(d.Hours() / 24)
		if days == 1 {
			return "tomorrow"
		}
		return fmt.Sprintf("in %d days", days)
	}
}

// TerminalWidth returns the current terminal width, or DefaultWidth if unknown.
func TerminalWidth() int {
	if w, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil && w > 0 {
		return w
	}
	return DefaultWidth
}

// Truncate shortens s to maxWidth, adding ellipsis if truncated.
// Properly handles ANSI escape codes and wide characters.
func Truncate(s string, maxWidth int) string {
	if maxWidth <= 0 {
		return ""
	}

	width := ansi.StringWidth(s)
	if width <= maxWidth {
		return s
	}

	if maxWidth == 1 {
		return Ellipsis
	}

	// Use ansi.Truncate which properly preserves ANSI sequences
	return ansi.Truncate(s, maxWidth-1, Ellipsis)
}

// Pad pads s to width with spaces according to alignment.
func Pad(s string, width int, align Alignment) string {
	displayW := ansi.StringWidth(s)
	if displayW >= width {
		return s
	}

	padding := width - displayW
	switch align {
	case AlignRight:
		return strings.Repeat(" ", padding) + s
	case AlignCenter:
		left := padding / 2
		right := padding - left
		return strings.Repeat(" ", left) + s + strings.Repeat(" ", right)
	default:
		return s + strings.Repeat(" ", padding)
	}
}


// Helper functions
func sum(vals []int) int {
	total := 0
	for _, v := range vals {
		total += v
	}
	return total
}
