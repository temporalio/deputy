package repl

import (
	"slices"
	"testing"
)

func TestDefaultTheme(t *testing.T) {
	theme := DefaultTheme()

	if theme.Name != "default" {
		t.Errorf("expected name 'default', got %q", theme.Name)
	}

	// Check symbols are set
	if theme.PromptSymbol == "" {
		t.Error("expected PromptSymbol to be set")
	}
	if theme.ResultSymbol == "" {
		t.Error("expected ResultSymbol to be set")
	}
	if theme.ErrorSymbol == "" {
		t.Error("expected ErrorSymbol to be set")
	}
}

func TestMinimalTheme(t *testing.T) {
	theme := MinimalTheme()

	if theme.Name != "minimal" {
		t.Errorf("expected name 'minimal', got %q", theme.Name)
	}

	// Should use ASCII symbols
	if theme.PromptSymbol != ">" {
		t.Errorf("expected ASCII prompt '>', got %q", theme.PromptSymbol)
	}
	if theme.ResultSymbol != "->" {
		t.Errorf("expected ASCII result '->', got %q", theme.ResultSymbol)
	}
	if theme.ErrorSymbol != "X" {
		t.Errorf("expected ASCII error 'X', got %q", theme.ErrorSymbol)
	}
}

func TestMonokaiTheme(t *testing.T) {
	theme := MonokaiTheme()

	if theme.Name != "monokai" {
		t.Errorf("expected name 'monokai', got %q", theme.Name)
	}
}

func TestDraculaTheme(t *testing.T) {
	theme := DraculaTheme()

	if theme.Name != "dracula" {
		t.Errorf("expected name 'dracula', got %q", theme.Name)
	}
}

func TestThemeByName(t *testing.T) {
	tests := []struct {
		name     string
		expected string
	}{
		{"default", "default"},
		{"minimal", "minimal"},
		{"monokai", "monokai"},
		{"dracula", "dracula"},
		{"unknown", "default"}, // Falls back to default
		{"", "default"},        // Empty falls back to default
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			theme := ThemeByName(tt.name)
			if theme.Name != tt.expected {
				t.Errorf("ThemeByName(%q) = %q, want %q", tt.name, theme.Name, tt.expected)
			}
		})
	}
}

func TestAvailableThemes(t *testing.T) {
	themes := AvailableThemes()

	expected := []string{"default", "minimal", "monokai", "dracula"}
	if len(themes) != len(expected) {
		t.Errorf("expected %d themes, got %d", len(expected), len(themes))
	}

	for _, name := range expected {
		found := slices.Contains(themes, name)
		if !found {
			t.Errorf("expected theme %q in available themes", name)
		}
	}
}

func TestTheme_StylesNotNil(t *testing.T) {
	themes := []struct {
		name  string
		theme *Theme
	}{
		{"default", DefaultTheme()},
		{"minimal", MinimalTheme()},
		{"monokai", MonokaiTheme()},
		{"dracula", DraculaTheme()},
	}

	for _, tt := range themes {
		t.Run(tt.name, func(t *testing.T) {
			theme := tt.theme

			// Test that styles can render without panic
			_ = theme.Prompt.Render("test")
			_ = theme.Context.Render("test")
			_ = theme.Result.Render("test")
			_ = theme.ResultFalse.Render("test")
			_ = theme.Error.Render("test")
			_ = theme.Warning.Render("test")
			_ = theme.Info.Render("test")
			_ = theme.Hint.Render("test")
			_ = theme.Ghost.Render("test")
			_ = theme.CompletionSelected.Render("test")
			_ = theme.CompletionNormal.Render("test")
			_ = theme.CompletionKind.Render("test")
			_ = theme.CompletionType.Render("test")
			_ = theme.CompletionDesc.Render("test")
			_ = theme.SyntaxKeyword.Render("test")
			_ = theme.SyntaxString.Render("test")
			_ = theme.SyntaxNumber.Render("test")
			_ = theme.SyntaxOperator.Render("test")
			_ = theme.SyntaxFunction.Render("test")
			_ = theme.SyntaxField.Render("test")
			_ = theme.SyntaxVariable.Render("test")
			_ = theme.SyntaxComment.Render("test")
			_ = theme.SyntaxEnum.Render("test")
			_ = theme.Key.Render("test")
			_ = theme.Value.Render("test")
			_ = theme.Label.Render("test")
			_ = theme.Divider.Render("test")
			_ = theme.Command.Render("test")
			_ = theme.Success.Render("test")
			_ = theme.Failure.Render("test")
		})
	}
}

func TestTheme_UniqueSymbols(t *testing.T) {
	theme := DefaultTheme()

	// Ensure symbols are visually distinct
	symbols := map[string]string{
		"PromptSymbol":   theme.PromptSymbol,
		"ContinueSymbol": theme.ContinueSymbol,
		"ResultSymbol":   theme.ResultSymbol,
		"ErrorSymbol":    theme.ErrorSymbol,
		"HintSymbol":     theme.HintSymbol,
	}

	// Check all symbols are non-empty
	for name, symbol := range symbols {
		if symbol == "" {
			t.Errorf("%s should not be empty", name)
		}
	}

	// Key symbols should be distinct
	if theme.PromptSymbol == theme.ErrorSymbol {
		t.Error("PromptSymbol and ErrorSymbol should be different")
	}
	if theme.ResultSymbol == theme.ErrorSymbol {
		t.Error("ResultSymbol and ErrorSymbol should be different")
	}
}
