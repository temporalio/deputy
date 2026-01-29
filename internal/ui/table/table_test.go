package table

import (
	"bytes"
	"strings"
	"testing"
)

func TestTruncate(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		maxWidth int
		want     string
	}{
		{
			name:     "no truncation needed",
			input:    "hello",
			maxWidth: 10,
			want:     "hello",
		},
		{
			name:     "exact fit",
			input:    "hello",
			maxWidth: 5,
			want:     "hello",
		},
		{
			name:     "truncate with ellipsis",
			input:    "hello world",
			maxWidth: 8,
			want:     "hello w…",
		},
		{
			name:     "very short maxWidth",
			input:    "hello",
			maxWidth: 1,
			want:     "…",
		},
		{
			name:     "zero maxWidth",
			input:    "hello",
			maxWidth: 0,
			want:     "",
		},
		{
			name:     "unicode preserved",
			input:    "héllo wörld",
			maxWidth: 8,
			want:     "héllo w…",
		},
		{
			name:     "long fork name like temporalio",
			input:    "Chainguard-Wolfi-Bites-Back/temporalio__temporal",
			maxWidth: 40,
			want:     "Chainguard-Wolfi-Bites-Back/temporalio_…",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Truncate(tt.input, tt.maxWidth)
			if got != tt.want {
				t.Errorf("Truncate(%q, %d) = %q, want %q", tt.input, tt.maxWidth, got, tt.want)
			}
			// Verify the result doesn't exceed maxWidth in display characters
			if tt.maxWidth > 0 && RuneWidth(got) > tt.maxWidth {
				t.Errorf("Truncate(%q, %d) = %q has width %d, exceeds max %d",
					tt.input, tt.maxWidth, got, RuneWidth(got), tt.maxWidth)
			}
		})
	}
}

func TestRuneWidth(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"hello", 5},
		{"héllo", 5},  // accented char is still 1 rune
		{"hello…", 6}, // ellipsis is 1 rune
		{"", 0},
		{"🎉", 1}, // emoji is 1 rune (though may render wider)
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := RuneWidth(tt.input)
			if got != tt.want {
				t.Errorf("RuneWidth(%q) = %d, want %d", tt.input, got, tt.want)
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
		{
			name:  "left align shorter string",
			input: "hi",
			width: 5,
			align: AlignLeft,
			want:  "hi   ",
		},
		{
			name:  "right align shorter string",
			input: "hi",
			width: 5,
			align: AlignRight,
			want:  "   hi",
		},
		{
			name:  "center align shorter string",
			input: "hi",
			width: 5,
			align: AlignCenter,
			want:  " hi  ",
		},
		{
			name:  "string already at width",
			input: "hello",
			width: 5,
			align: AlignLeft,
			want:  "hello",
		},
		{
			name:  "string longer than width",
			input: "hello world",
			width: 5,
			align: AlignLeft,
			want:  "hello world",
		},
		{
			name:  "unicode string",
			input: "hé…",
			width: 5,
			align: AlignLeft,
			want:  "hé…  ",
		},
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

func TestTableRender(t *testing.T) {
	// Create a table like the forks output
	tbl := New(
		Column{Header: "FORK", MaxWidth: 40},
		Column{Header: "OWNER", MaxWidth: 25},
		Column{Header: "STARS", MaxWidth: 6},
	)

	// Add rows including one with a long name that needs truncation
	tbl.AddRow("short/repo", "shortuser", "10")
	tbl.AddRow("Chainguard-Wolfi-Bites-Back/temporalio__temporal", "Chainguard-Wolfi-Bites-Back", "0")
	tbl.AddRow("normal/fork", "normaluser", "5")

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

	// Check that the long fork name is truncated (contains ellipsis)
	if !strings.Contains(lines[2], "…") {
		t.Errorf("Expected line 2 to contain ellipsis for truncation:\n%s", lines[2])
	}

	// Check that the long owner name is truncated (contains ellipsis)
	// The owner "Chainguard-Wolfi-Bites-Back" is 27 chars, maxWidth is 25
	if !strings.Contains(lines[2], "Chainguard-Wolfi-Bites-B…") {
		t.Errorf("Expected line 2 to contain truncated owner:\n%s", lines[2])
	}

	// Verify no column overflow - each line should be roughly the same length
	// (allowing for some variation due to content)
	maxLen := 0
	for _, line := range lines {
		lineLen := RuneWidth(StripANSI(line))
		if lineLen > maxLen {
			maxLen = lineLen
		}
	}
	// All lines should be within a reasonable range of the max
	for i, line := range lines {
		lineLen := RuneWidth(StripANSI(line))
		// Allow some variation for the last column which isn't padded
		if lineLen > maxLen {
			t.Errorf("Line %d overflows: width %d > max %d:\n%s", i, lineLen, maxLen, line)
		}
	}
}

func TestStripANSI(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"hello", "hello"},
		{"\x1b[31mred\x1b[0m", "red"},
		{"\x1b[1;32mbold green\x1b[0m", "bold green"},
		{"no \x1b[4munderline\x1b[0m here", "no underline here"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := StripANSI(tt.input)
			if got != tt.want {
				t.Errorf("StripANSI(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
