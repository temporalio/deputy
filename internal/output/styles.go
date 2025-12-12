package output

import ui "github.com/picatz/deputy/internal/ui"

// Styles holds formatting functions for the text renderer.
// Plain styles can be used in tests for stable golden output.
type Styles struct {
	Header      func(string) string
	PackageName func(string) string
	Version     func(string) string
	Meta        func(string) string
	Dim         func(string) string
	Added       func(string) string
	Bold        func(string) string
	Upgraded    func(string) string
	Removed     func(string) string
	Symbol      func(string) string
}

// UIStyles returns styles backed by the internal/ui lipgloss palette.
func UIStyles() Styles {
	wrap := func(f func(...string) string) func(string) string {
		return func(s string) string { return f(s) }
	}
	return Styles{
		Header:      wrap(ui.StyleHeader.Render),
		PackageName: wrap(ui.StylePackageName.Render),
		Version:     wrap(ui.StyleVersion.Render),
		Meta:        wrap(ui.StyleMeta.Render),
		Dim:         wrap(ui.StyleDim.Render),
		Added:       wrap(ui.StyleAdded.Render),
		Bold:        wrap(ui.StyleBold.Render),
		Upgraded:    wrap(ui.StyleUpgraded.Render),
		Removed:     wrap(ui.StyleRemoved.Render),
		Symbol:      wrap(ui.StyleSymbol.Render),
	}
}

// PlainStyles returns identity styles suitable for golden tests.
func PlainStyles() Styles {
	id := func(s string) string { return s }
	return Styles{
		Header:      id,
		PackageName: id,
		Version:     id,
		Meta:        id,
		Dim:         id,
		Added:       id,
		Bold:        id,
		Upgraded:    id,
		Removed:     id,
		Symbol:      id,
	}
}
