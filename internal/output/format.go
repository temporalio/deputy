package output

import (
	"encoding/csv"
	"encoding/json"
	"io"
	"reflect"
	"strings"
)

// Format represents an output format type.
type Format string

// Supported output formats.
const (
	FormatTable    Format = "table"
	FormatJSON     Format = "json"
	FormatSARIF    Format = "sarif"
	FormatCSV      Format = "csv"
	FormatMarkdown Format = "markdown"
)

// AllFormats returns all supported output formats.
func AllFormats() []Format {
	return []Format{FormatTable, FormatJSON, FormatSARIF, FormatCSV, FormatMarkdown}
}

// ParseFormat converts a string to a Format, defaulting to table.
// Returns the format and whether it was recognized.
func ParseFormat(s string) Format {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "json":
		return FormatJSON
	case "sarif":
		return FormatSARIF
	case "csv":
		return FormatCSV
	case "markdown", "md":
		return FormatMarkdown
	default:
		return FormatTable
	}
}

// IsValid reports whether this is a recognized format.
func (f Format) IsValid() bool {
	switch f {
	case FormatTable, FormatJSON, FormatSARIF, FormatCSV, FormatMarkdown:
		return true
	default:
		return false
	}
}

// String returns the format name.
func (f Format) String() string {
	return string(f)
}

// IsJSON returns true for JSON-based formats (json, sarif).
func (f Format) IsJSON() bool {
	return f == FormatJSON || f == FormatSARIF
}

// Formatter defines the interface for rendering scan/diff/sbom results.
// Each format (table, JSON, SARIF) implements this interface.
type Formatter[T any] interface {
	// Format renders the result to the writer.
	Format(w io.Writer, result T) error
}

// FormatterFunc is a function adapter for Formatter.
type FormatterFunc[T any] func(w io.Writer, result T) error

// Format implements Formatter.
func (f FormatterFunc[T]) Format(w io.Writer, result T) error {
	return f(w, result)
}

// JSONFormatter creates a formatter that outputs JSON.
func JSONFormatter[T any]() Formatter[T] {
	return FormatterFunc[T](func(w io.Writer, result T) error {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	})
}

// JSONFormatterCompact creates a formatter that outputs compact JSON (no indentation).
func JSONFormatterCompact[T any]() Formatter[T] {
	return FormatterFunc[T](func(w io.Writer, result T) error {
		return json.NewEncoder(w).Encode(result)
	})
}

// MultiFormatter combines multiple formatters, running each in sequence.
// Useful for writing to multiple outputs (e.g., terminal + file).
type MultiFormatter[T any] struct {
	formatters []Formatter[T]
}

// NewMultiFormatter creates a formatter that writes to multiple outputs.
func NewMultiFormatter[T any](formatters ...Formatter[T]) *MultiFormatter[T] {
	return &MultiFormatter[T]{formatters: formatters}
}

// Format runs all formatters in sequence.
func (m *MultiFormatter[T]) Format(w io.Writer, result T) error {
	for _, f := range m.formatters {
		if err := f.Format(w, result); err != nil {
			return err
		}
	}
	return nil
}

// CSVRecord defines the interface for types that can be converted to CSV rows.
type CSVRecord interface {
	// CSVHeaders returns the column headers for CSV output.
	CSVHeaders() []string
	// CSVRow returns the values for a single CSV row.
	CSVRow() []string
}

// CSVFormatter creates a formatter that outputs CSV for a slice of records.
// The type T must be a slice of types implementing CSVRecord.
func CSVFormatter[T ~[]E, E CSVRecord]() Formatter[T] {
	return FormatterFunc[T](func(w io.Writer, records T) error {
		cw := csv.NewWriter(w)
		defer cw.Flush()

		if len(records) == 0 {
			return nil
		}

		// Write headers from first record
		if err := cw.Write(records[0].CSVHeaders()); err != nil {
			return err
		}

		// Write data rows
		for _, record := range records {
			if err := cw.Write(record.CSVRow()); err != nil {
				return err
			}
		}

		return cw.Error()
	})
}

// CSVFormatterWithHeaders creates a CSV formatter with custom headers.
// Useful when you want different headers than what CSVHeaders() returns.
func CSVFormatterWithHeaders[T ~[]E, E CSVRecord](headers []string) Formatter[T] {
	return FormatterFunc[T](func(w io.Writer, records T) error {
		cw := csv.NewWriter(w)
		defer cw.Flush()

		if err := cw.Write(headers); err != nil {
			return err
		}

		for _, record := range records {
			if err := cw.Write(record.CSVRow()); err != nil {
				return err
			}
		}

		return cw.Error()
	})
}

// StructToCSVRow converts a struct to a CSV row using reflection.
// Fields are extracted in order, using json tags for naming if present.
// This is a convenience for simple structs; for performance-critical code,
// implement CSVRecord directly.
func StructToCSVRow(v any) (headers, values []string) {
	val := reflect.ValueOf(v)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}
	if val.Kind() != reflect.Struct {
		return nil, nil
	}

	typ := val.Type()
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if !field.IsExported() {
			continue
		}

		// Use json tag name if available
		name := field.Name
		if tag := field.Tag.Get("json"); tag != "" {
			parts := strings.Split(tag, ",")
			if parts[0] != "" && parts[0] != "-" {
				name = parts[0]
			}
		}

		headers = append(headers, name)
		values = append(values, formatValue(val.Field(i)))
	}
	return headers, values
}

// formatValue converts a reflect.Value to a string for CSV output.
func formatValue(v reflect.Value) string {
	if !v.IsValid() {
		return ""
	}

	switch v.Kind() {
	case reflect.Ptr, reflect.Interface:
		if v.IsNil() {
			return ""
		}
		return formatValue(v.Elem())
	case reflect.Slice, reflect.Array:
		if v.Len() == 0 {
			return ""
		}
		var parts []string
		for i := 0; i < v.Len(); i++ {
			parts = append(parts, formatValue(v.Index(i)))
		}
		return strings.Join(parts, ";")
	case reflect.Map:
		if v.Len() == 0 {
			return ""
		}
		var parts []string
		iter := v.MapRange()
		for iter.Next() {
			parts = append(parts, formatValue(iter.Key())+"="+formatValue(iter.Value()))
		}
		return strings.Join(parts, ";")
	default:
		return strings.TrimSpace(strings.ReplaceAll(v.String(), "\n", " "))
	}
}
