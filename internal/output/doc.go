package output

import (
	"fmt"
	"io"
	"strings"
)

// Style identifies which style function to apply to a span.
type Style uint8

const (
	StyleNone Style = iota
	StyleHeader
	StylePackageName
	StyleVersion
	StyleMeta
	StyleDim
	StyleAdded
	StyleBold
	StyleUpgraded
	StyleRemoved
	StyleSymbol
)

// Span is a piece of text with an associated style.
type Span struct {
	Text  string
	Style Style
}

// Line is a sequence of spans rendered on a single line.
type Line []Span

// Doc is a lightweight document model that can be rendered to an io.Writer.
type Doc struct {
	Lines []Line
}

// AddLine appends a line.
func (d *Doc) AddLine(parts ...Span) {
	d.Lines = append(d.Lines, parts)
}

// AddBlank appends a blank line.
func (d *Doc) AddBlank() {
	d.Lines = append(d.Lines, nil)
}

// Render writes the document to w using the provided styles.
func (d Doc) Render(w io.Writer, styles Styles) error {
	for i, line := range d.Lines {
		if i > 0 {
			if _, err := io.WriteString(w, "\n"); err != nil {
				return err
			}
		}
		if len(line) == 0 {
			continue
		}
		var b strings.Builder
		for _, s := range line {
			text := s.Text
			switch s.Style {
			case StyleHeader:
				text = styles.Header(text)
			case StylePackageName:
				text = styles.PackageName(text)
			case StyleVersion:
				text = styles.Version(text)
			case StyleMeta:
				text = styles.Meta(text)
			case StyleDim:
				text = styles.Dim(text)
			case StyleAdded:
				text = styles.Added(text)
			case StyleBold:
				text = styles.Bold(text)
			case StyleUpgraded:
				text = styles.Upgraded(text)
			case StyleRemoved:
				text = styles.Removed(text)
			case StyleSymbol:
				text = styles.Symbol(text)
			case StyleNone:
				// no-op
			default:
				return fmt.Errorf("unknown style %d", s.Style)
			}
			b.WriteString(text)
		}
		if _, err := io.WriteString(w, b.String()); err != nil {
			return err
		}
	}
	if len(d.Lines) > 0 {
		if _, err := io.WriteString(w, "\n"); err != nil {
			return err
		}
	}
	return nil
}
