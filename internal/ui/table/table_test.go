package table

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/x/ansi"
)

func TestTruncate(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		maxWidth int
		want     string
	}{
		{"no truncation needed", "hello", 10, "hello"},
		{"exact fit", "hello", 5, "hello"},
		{"truncate with ellipsis", "hello world", 8, "hello …"},
		{"very short maxWidth", "hello", 1, "…"},
		{"zero maxWidth", "hello", 0, ""},
		{"unicode preserved", "héllo wörld", 8, "héllo …"},
		{"long fork name", "Chainguard-Wolfi-Bites-Back/temporalio__temporal", 40, "Chainguard-Wolfi-Bites-Back/temporalio…"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Truncate(tt.input, tt.maxWidth)
			if got != tt.want {
				t.Errorf("Truncate(%q, %d) = %q, want %q", tt.input, tt.maxWidth, got, tt.want)
			}
			if tt.maxWidth > 0 && ansi.StringWidth(got) > tt.maxWidth {
				t.Errorf("Truncate result exceeds maxWidth: %d > %d", ansi.StringWidth(got), tt.maxWidth)
			}
		})
	}
}

func TestPad(t *testing.T) {
	tests := []struct {
		name  string
		input string
		width int
		align Alignment
		want  string
	}{
		{"left align", "hi", 5, AlignLeft, "hi   "},
		{"right align", "hi", 5, AlignRight, "   hi"},
		{"center align", "hi", 5, AlignCenter, " hi  "},
		{"exact width", "hello", 5, AlignLeft, "hello"},
		{"overflow", "hello world", 5, AlignLeft, "hello world"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Pad(tt.input, tt.width, tt.align)
			if got != tt.want {
				t.Errorf("Pad(%q, %d, %v) = %q, want %q", tt.input, tt.width, tt.align, got, tt.want)
			}
		})
	}
}

func TestRelativeTime(t *testing.T) {
	now := time.Date(2026, 1, 28, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name string
		t    time.Time
		want string
	}{
		{"just now", now.Add(-30 * time.Second), "just now"},
		{"1 min ago", now.Add(-1 * time.Minute), "1 min ago"},
		{"5 mins ago", now.Add(-5 * time.Minute), "5 mins ago"},
		{"1 hour ago", now.Add(-1 * time.Hour), "1 hour ago"},
		{"3 hours ago", now.Add(-3 * time.Hour), "3 hours ago"},
		{"yesterday", now.Add(-36 * time.Hour), "yesterday"},
		{"3 days ago", now.Add(-3 * 24 * time.Hour), "3 days ago"},
		{"1 week ago", now.Add(-10 * 24 * time.Hour), "1 week ago"},
		{"3 weeks ago", now.Add(-21 * 24 * time.Hour), "3 weeks ago"},
		{"1 month ago", now.Add(-45 * 24 * time.Hour), "1 month ago"},
		{"6 months ago", now.Add(-180 * 24 * time.Hour), "6 months ago"},
		{"1 year ago", now.Add(-400 * 24 * time.Hour), "1 year ago"},
		{"2 years ago", now.Add(-800 * 24 * time.Hour), "2 years ago"},
		{"zero time", time.Time{}, "-"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RelativeTime(tt.t, now)
			if got != tt.want {
				t.Errorf("RelativeTime() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTableFluidLayout(t *testing.T) {
	tbl := New(
		Column{Header: "FORK", Type: TypeID, Priority: 2, MaxWidth: 40},
		Column{Header: "OWNER", Type: TypeText, Priority: 1, MaxWidth: 25},
		Column{Header: "STARS", Type: TypeNumber, Priority: 0},
		Column{Header: "CREATED", Type: TypeDate, Priority: 0},
	)
	tbl.SetWidth(100) // Simulate narrow terminal
	tbl.SetNow(time.Date(2026, 1, 28, 12, 0, 0, 0, time.UTC))

	// Add rows with varying content
	tbl.AddRow("short/repo", "shortuser", "10", "2025-01-15")
	tbl.AddRow("Chainguard-Wolfi-Bites-Back/temporalio__temporal", "Chainguard-Wolfi-Bites-Back", "0", "2024-06-08")
	tbl.AddRow("normal/fork", "normaluser", "12500", "2020-08-26")

	var buf bytes.Buffer
	err := tbl.Render(&buf, true)
	if err != nil {
		t.Fatalf("Render failed: %v", err)
	}

	output := buf.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")

	// Should have 4 lines: header + 3 data rows
	if len(lines) != 4 {
		t.Errorf("Expected 4 lines, got %d:\n%s", len(lines), output)
	}

	// Verify truncation happened (ellipsis present)
	if !strings.Contains(output, "…") {
		t.Error("Expected truncation with ellipsis in narrow terminal")
	}

	// Verify relative dates are used
	if !strings.Contains(output, "year") && !strings.Contains(output, "ago") {
		t.Error("Expected relative date format")
	}
}

func TestTableWideTerminal(t *testing.T) {
	tbl := New(
		Column{Header: "NAME", Type: TypeID, Priority: 2},
		Column{Header: "DESCRIPTION", Type: TypeText, Priority: 1},
		Column{Header: "COUNT", Type: TypeNumber},
	)
	tbl.SetWidth(200) // Wide terminal

	tbl.AddRow("short-name", "A brief description", "42")
	tbl.AddRow("longer-name-here", "A much longer description that should not be truncated", "100")

	var buf bytes.Buffer
	tbl.Render(&buf, true)

	output := buf.String()

	// With a wide terminal, content should NOT be truncated
	if strings.Contains(output, "…") {
		t.Error("Wide terminal should not truncate content")
	}

	// Full description should be present
	if !strings.Contains(output, "should not be truncated") {
		t.Error("Wide terminal should show full content")
	}
}

func TestTableValueTypes(t *testing.T) {
	tbl := New(
		Column{Header: "NAME", Type: TypeID},
		Column{Header: "STATUS", Type: TypeStatus},
		Column{Header: "STARS", Type: TypeNumber},
		Column{Header: "DATE", Type: TypeDate},
	)
	tbl.SetWidth(100)
	tbl.SetNow(time.Date(2026, 1, 28, 12, 0, 0, 0, time.UTC))

	// Use dates that will produce "ago" in relative format
	tbl.AddRow("test-repo", "open", "0", "2026-01-20")      // 8 days ago -> "1 week ago"
	tbl.AddRow("another", "closed", "5000", "2024-01-01")   // 2 years ago
	tbl.AddRow("third", "merged", "150", "2025-06-15")      // 7 months ago

	var buf bytes.Buffer
	tbl.Render(&buf, true)

	output := buf.String()

	// Check output contains expected content
	if !strings.Contains(output, "test-repo") {
		t.Error("Missing name in output")
	}

	// Relative dates should be present (at least one "ago")
	if !strings.Contains(output, "ago") {
		t.Errorf("Expected relative dates with 'ago' in output, got:\n%s", output)
	}
}

func TestTypeDateFull(t *testing.T) {
	tbl := New(
		Column{Header: "NAME", Type: TypeID, MinWidth: 10},
		Column{Header: "CREATED", Type: TypeDateFull, MinWidth: 30},
	)
	tbl.SetWidth(200) // Wide terminal to show full date format
	tbl.SetNow(time.Date(2026, 1, 28, 12, 0, 0, 0, time.UTC))

	tbl.AddRow("test-item", "2024-06-15")

	var buf bytes.Buffer
	tbl.Render(&buf, true)

	output := buf.String()

	// Should contain the date in YYYY-MM-DD format
	if !strings.Contains(output, "2024-06-15") {
		t.Errorf("Expected date '2024-06-15' in output, got:\n%s", output)
	}

	// Should contain the relative time in brackets
	if !strings.Contains(output, "[") || !strings.Contains(output, "]") {
		t.Errorf("Expected brackets around relative time in output, got:\n%s", output)
	}

	// Should contain "year" or "months" since it's a past date (June 2024 -> Jan 2026 = ~1.5 years)
	if !strings.Contains(output, "year") && !strings.Contains(output, "months") {
		t.Errorf("Expected relative time indicator in output, got:\n%s", output)
	}
}

func TestFormatNumber(t *testing.T) {
	tests := []struct {
		input   string
		wantRaw string
	}{
		{"0", "0"},
		{"42", "42"},
		{"500", "500"},
		{"15000", "15000"},
		{"-", "-"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			gotRaw, _ := formatNumber(tt.input)
			if gotRaw != tt.wantRaw {
				t.Errorf("formatNumber(%q) raw = %q, want %q", tt.input, gotRaw, tt.wantRaw)
			}
		})
	}
}

func TestFormatStatus(t *testing.T) {
	// Just verify it returns something for known statuses
	statuses := []string{"open", "closed", "merged", "failed", "pending", "direct", "indirect", "unknown"}
	for _, s := range statuses {
		result := formatStatus(s)
		if result == "" {
			t.Errorf("formatStatus(%q) returned empty string", s)
		}
	}
}

func TestFormatDigest(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantRaw string
	}{
		{"full sha256", "sha256:abc123def456", "sha256:abc123def456"},
		{"sha512", "sha512:fedcba987654", "sha512:fedcba987654"},
		{"empty", "", ""},
		{"dash", "-", "-"},
		{"no colon", "abc123", "abc123"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotRaw, gotStyled := formatDigest(tt.input)
			if gotRaw != tt.wantRaw {
				t.Errorf("formatDigest(%q) raw = %q, want %q", tt.input, gotRaw, tt.wantRaw)
			}
			// Styled should never be empty if input wasn't empty
			if tt.input != "" && gotStyled == "" {
				t.Errorf("formatDigest(%q) styled was empty", tt.input)
			}
		})
	}
}

func TestTypeDigest(t *testing.T) {
	tbl := New(
		Column{Header: "TAG", Type: TypeID, MinWidth: 10},
		Column{Header: "DIGEST", Type: TypeDigest, MinWidth: 20},
	)
	tbl.SetWidth(100)

	tbl.AddRow("latest", "sha256:abc123def456789")
	tbl.AddRow("v1.0.0", "sha256:fedcba987654321")

	var buf bytes.Buffer
	tbl.Render(&buf, true)

	output := buf.String()

	// Should contain the digests
	if !strings.Contains(output, "sha256") {
		t.Errorf("Expected 'sha256' in output, got:\n%s", output)
	}

	// Should contain the hash parts
	if !strings.Contains(output, "abc123") {
		t.Errorf("Expected hash part in output, got:\n%s", output)
	}
}
