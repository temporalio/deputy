package output

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestParseFormat(t *testing.T) {
	tests := []struct {
		input string
		want  Format
	}{
		{"json", FormatJSON},
		{"sarif", FormatSARIF},
		{"table", FormatTable},
		{"csv", FormatCSV},
		{"markdown", FormatMarkdown},
		{"", FormatTable},
		{"unknown", FormatTable},
	}
	for _, tt := range tests {
		if got := ParseFormat(tt.input); got != tt.want {
			t.Errorf("ParseFormat(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestFormatIsJSON(t *testing.T) {
	tests := []struct {
		format Format
		want   bool
	}{
		{FormatJSON, true},
		{FormatSARIF, true},
		{FormatTable, false},
	}
	for _, tt := range tests {
		if got := tt.format.IsJSON(); got != tt.want {
			t.Errorf("%v.IsJSON() = %v, want %v", tt.format, got, tt.want)
		}
	}
}

func TestJSONFormatter(t *testing.T) {
	type data struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}
	formatter := JSONFormatter[data]()

	var buf bytes.Buffer
	err := formatter.Format(&buf, data{Name: "test", Count: 42})
	if err != nil {
		t.Fatalf("Format error: %v", err)
	}

	got := strings.TrimSpace(buf.String())
	want := `{
  "name": "test",
  "count": 42
}`
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestJSONFormatterCompact(t *testing.T) {
	type data struct {
		Name string `json:"name"`
	}
	formatter := JSONFormatterCompact[data]()

	var buf bytes.Buffer
	err := formatter.Format(&buf, data{Name: "test"})
	if err != nil {
		t.Fatalf("Format error: %v", err)
	}

	got := strings.TrimSpace(buf.String())
	want := `{"name":"test"}`
	if got != want {
		t.Errorf("got: %s, want: %s", got, want)
	}
}

func TestFormatterFunc(t *testing.T) {
	called := false
	formatter := FormatterFunc[string](func(w io.Writer, result string) error {
		called = true
		_, err := w.Write([]byte(result))
		return err
	})

	var buf bytes.Buffer
	if err := formatter.Format(&buf, "hello"); err != nil {
		t.Fatalf("Format error: %v", err)
	}
	if !called {
		t.Error("FormatterFunc was not called")
	}
	if buf.String() != "hello" {
		t.Errorf("got %q, want %q", buf.String(), "hello")
	}
}

func TestMultiFormatter(t *testing.T) {
	var buf1, buf2 bytes.Buffer
	formatter := NewMultiFormatter(
		FormatterFunc[string](func(w io.Writer, s string) error {
			buf1.WriteString(s)
			return nil
		}),
		FormatterFunc[string](func(w io.Writer, s string) error {
			buf2.WriteString(s)
			return nil
		}),
	)

	// Note: MultiFormatter writes to the same writer, but we're using side effects
	var sink bytes.Buffer
	if err := formatter.Format(&sink, "test"); err != nil {
		t.Fatalf("Format error: %v", err)
	}
	if buf1.String() != "test" {
		t.Errorf("buf1 = %q, want %q", buf1.String(), "test")
	}
	if buf2.String() != "test" {
		t.Errorf("buf2 = %q, want %q", buf2.String(), "test")
	}
}

// testCSVRecord implements CSVRecord for testing.
type testCSVRecord struct {
	Name  string
	Count int
}

func (r testCSVRecord) CSVHeaders() []string {
	return []string{"name", "count"}
}

func (r testCSVRecord) CSVRow() []string {
	return []string{r.Name, strings.Repeat("x", r.Count)}
}

func TestCSVFormatter(t *testing.T) {
	records := []testCSVRecord{
		{Name: "first", Count: 1},
		{Name: "second", Count: 2},
	}

	formatter := CSVFormatter[[]testCSVRecord, testCSVRecord]()

	var buf bytes.Buffer
	if err := formatter.Format(&buf, records); err != nil {
		t.Fatalf("Format error: %v", err)
	}

	got := buf.String()
	want := "name,count\nfirst,x\nsecond,xx\n"
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestCSVFormatterEmpty(t *testing.T) {
	var records []testCSVRecord

	formatter := CSVFormatter[[]testCSVRecord, testCSVRecord]()

	var buf bytes.Buffer
	if err := formatter.Format(&buf, records); err != nil {
		t.Fatalf("Format error: %v", err)
	}

	got := buf.String()
	if got != "" {
		t.Errorf("expected empty output for empty slice, got: %q", got)
	}
}

func TestAllFormats(t *testing.T) {
	formats := AllFormats()
	// Should include at least table, json, sarif, csv, markdown
	if len(formats) < 5 {
		t.Errorf("AllFormats() returned %d formats, expected at least 5", len(formats))
	}

	// Check that table format is included
	found := false
	for _, f := range formats {
		if f == FormatTable {
			found = true
			break
		}
	}
	if !found {
		t.Error("AllFormats() should include FormatTable")
	}
}

func TestFormatIsValid(t *testing.T) {
	tests := []struct {
		format Format
		want   bool
	}{
		{FormatTable, true},
		{FormatJSON, true},
		{FormatSARIF, true},
		{FormatCSV, true},
		{FormatMarkdown, true},
		{Format("invalid"), false},
		{Format(""), false},
	}
	for _, tt := range tests {
		if got := tt.format.IsValid(); got != tt.want {
			t.Errorf("%q.IsValid() = %v, want %v", tt.format, got, tt.want)
		}
	}
}
