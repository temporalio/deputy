package output

import (
	"encoding/json"
	"io"
)

// Format represents an output format type.
type Format string

// Supported output formats.
const (
	FormatTable Format = "table"
	FormatJSON  Format = "json"
	FormatSARIF Format = "sarif"
)

// ParseFormat converts a string to a Format, defaulting to table.
func ParseFormat(s string) Format {
	switch s {
	case "json":
		return FormatJSON
	case "sarif":
		return FormatSARIF
	default:
		return FormatTable
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
