package repl

import (
	"bytes"
	"strings"
	"testing"
)

func TestNewEngine(t *testing.T) {
	var in, out bytes.Buffer
	engine := NewEngine(&in, &out, nil)

	if engine == nil {
		t.Fatal("expected engine to be created")
	}

	if engine.Config() == nil {
		t.Error("expected default config")
	}

	if engine.Schema() == nil {
		t.Error("expected schema registry")
	}

	if engine.Completion() == nil {
		t.Error("expected completion engine")
	}
}

func TestEngine_Output_Prompt(t *testing.T) {
	var out bytes.Buffer
	engine := NewEngine(nil, &out, nil)

	engine.Output().Prompt("proxy")

	output := out.String()
	if !strings.Contains(output, "proxy") {
		t.Errorf("expected 'proxy' in prompt, got: %s", output)
	}
	if !strings.Contains(output, "cel") {
		t.Errorf("expected 'cel' in prompt, got: %s", output)
	}
}

func TestEngine_Output_Result(t *testing.T) {
	tests := []struct {
		name     string
		value    any
		typeName string
		contains []string
	}{
		{
			name:     "true boolean",
			value:    true,
			typeName: "bool",
			contains: []string{"true", "bool"},
		},
		{
			name:     "false boolean",
			value:    false,
			typeName: "bool",
			contains: []string{"false", "bool"},
		},
		{
			name:     "string value",
			value:    "CRITICAL",
			typeName: "string",
			contains: []string{"CRITICAL", "string"},
		},
		{
			name:     "integer value",
			value:    42,
			typeName: "int",
			contains: []string{"42", "int"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			engine := NewEngine(nil, &out, nil)

			engine.Output().Result(tt.value, tt.typeName)

			output := out.String()
			for _, expected := range tt.contains {
				if !strings.Contains(output, expected) {
					t.Errorf("expected %q in output, got: %s", expected, output)
				}
			}
		})
	}
}

func TestEngine_Output_Error(t *testing.T) {
	var out bytes.Buffer
	engine := NewEngine(nil, &out, nil)

	engine.Output().Error("something went wrong")

	output := out.String()
	if !strings.Contains(output, "something went wrong") {
		t.Errorf("expected error message, got: %s", output)
	}
}

func TestEngine_Output_ErrorWithHint(t *testing.T) {
	var out bytes.Buffer
	engine := NewEngine(nil, &out, nil)

	engine.Output().ErrorWithHint("undefined variable", "check :vars for available variables")

	output := out.String()
	if !strings.Contains(output, "undefined variable") {
		t.Errorf("expected error message, got: %s", output)
	}
	if !strings.Contains(output, "hint:") {
		t.Errorf("expected hint prefix, got: %s", output)
	}
	if !strings.Contains(output, ":vars") {
		t.Errorf("expected hint content, got: %s", output)
	}
}

func TestEngine_Output_Section(t *testing.T) {
	var out bytes.Buffer
	engine := NewEngine(nil, &out, nil)

	engine.Output().Section("Helper Functions")

	output := out.String()
	if !strings.Contains(output, "Helper Functions") {
		t.Errorf("expected section title, got: %s", output)
	}
}

func TestEngine_Output_KeyValue(t *testing.T) {
	var out bytes.Buffer
	engine := NewEngine(nil, &out, nil)

	engine.Output().KeyValue("severity.CRITICAL", "CRITICAL")

	output := out.String()
	if !strings.Contains(output, "severity.CRITICAL") {
		t.Errorf("expected key, got: %s", output)
	}
	if !strings.Contains(output, "=") {
		t.Errorf("expected equals sign, got: %s", output)
	}
	if !strings.Contains(output, "CRITICAL") {
		t.Errorf("expected value, got: %s", output)
	}
}

func TestEngine_Output_CommandHelp(t *testing.T) {
	var out bytes.Buffer
	engine := NewEngine(nil, &out, nil)

	engine.Output().CommandHelp(":set key=value", "set a request field")

	output := out.String()
	if !strings.Contains(output, ":set key=value") {
		t.Errorf("expected command, got: %s", output)
	}
	if !strings.Contains(output, "set a request field") {
		t.Errorf("expected description, got: %s", output)
	}
}

func TestEngine_HighlightCEL(t *testing.T) {
	var out bytes.Buffer
	engine := NewEngine(nil, &out, nil)

	// Should not panic and should return something
	result := engine.HighlightCEL(`vulnerability.severity == "CRITICAL"`)
	if result == "" {
		t.Error("expected non-empty highlighted result")
	}

	// Should contain the expression content
	if !strings.Contains(result, "vulnerability") {
		t.Error("expected 'vulnerability' in highlighted output")
	}
}

func TestEngine_HighlightCEL_Disabled(t *testing.T) {
	var out bytes.Buffer
	config := DefaultConfig()
	config.HighlightSyntax = false
	engine := NewEngine(nil, &out, config)

	input := `severity.CRITICAL`
	result := engine.HighlightCEL(input)

	// Should return input unchanged when disabled
	if result != input {
		t.Errorf("expected %q when highlighting disabled, got %q", input, result)
	}
}

func TestEngine_Complete(t *testing.T) {
	var out bytes.Buffer
	engine := NewEngine(nil, &out, nil)

	completions := engine.Complete("sev", 3)
	if len(completions) == 0 {
		t.Fatal("expected completions for 'sev'")
	}

	// Should include severity-related items
	found := false
	for _, c := range completions {
		if strings.HasPrefix(c.Text, "sev") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected completions starting with 'sev'")
	}
}

func TestEngine_GetHint(t *testing.T) {
	var out bytes.Buffer
	engine := NewEngine(nil, &out, nil)

	hint := engine.GetHint("vulner", 6)
	if hint == nil {
		t.Fatal("expected hint for partial 'vulner'")
	}
	if hint.Text == "" {
		t.Error("expected non-empty hint text")
	}
}

func TestEngine_GetHint_Disabled(t *testing.T) {
	var out bytes.Buffer
	config := DefaultConfig()
	config.ShowHints = false
	engine := NewEngine(nil, &out, config)

	hint := engine.GetHint("vulner", 6)
	if hint != nil {
		t.Error("expected no hint when disabled")
	}
}

func TestEngine_History(t *testing.T) {
	var out bytes.Buffer
	engine := NewEngine(nil, &out, nil)

	// Add items to history
	engine.AddToHistory("first command")
	engine.AddToHistory("second command")
	engine.AddToHistory("third command")

	// Navigate back
	prev := engine.HistoryPrev()
	if prev != "third command" {
		t.Errorf("expected 'third command', got %q", prev)
	}

	prev = engine.HistoryPrev()
	if prev != "second command" {
		t.Errorf("expected 'second command', got %q", prev)
	}

	prev = engine.HistoryPrev()
	if prev != "first command" {
		t.Errorf("expected 'first command', got %q", prev)
	}

	// At beginning, should return empty
	prev = engine.HistoryPrev()
	if prev != "" {
		t.Errorf("expected empty at beginning, got %q", prev)
	}

	// Navigate forward
	next := engine.HistoryNext()
	if next != "second command" {
		t.Errorf("expected 'second command', got %q", next)
	}

	next = engine.HistoryNext()
	if next != "third command" {
		t.Errorf("expected 'third command', got %q", next)
	}

	// At end, should return empty
	next = engine.HistoryNext()
	if next != "" {
		t.Errorf("expected empty at end, got %q", next)
	}
}

func TestEngine_History_NoDuplicates(t *testing.T) {
	var out bytes.Buffer
	engine := NewEngine(nil, &out, nil)

	engine.AddToHistory("same command")
	engine.AddToHistory("same command")
	engine.AddToHistory("same command")

	// Should only have one entry
	count := 0
	for engine.HistoryPrev() != "" {
		count++
	}
	if count != 1 {
		t.Errorf("expected 1 history entry, got %d", count)
	}
}

func TestEngine_History_IgnoresEmpty(t *testing.T) {
	var out bytes.Buffer
	engine := NewEngine(nil, &out, nil)

	engine.AddToHistory("")
	engine.AddToHistory("valid")
	engine.AddToHistory("")

	prev := engine.HistoryPrev()
	if prev != "valid" {
		t.Errorf("expected 'valid', got %q", prev)
	}

	prev = engine.HistoryPrev()
	if prev != "" {
		t.Errorf("expected empty (no empty strings in history), got %q", prev)
	}
}

func TestEngine_SetTheme(t *testing.T) {
	var out bytes.Buffer
	engine := NewEngine(nil, &out, nil)

	// Default theme
	if engine.Config().Theme.Name != "default" {
		t.Errorf("expected default theme, got %q", engine.Config().Theme.Name)
	}

	// Change to monokai
	engine.SetTheme("monokai")
	if engine.Config().Theme.Name != "monokai" {
		t.Errorf("expected monokai theme, got %q", engine.Config().Theme.Name)
	}

	// Unknown theme falls back to default
	engine.SetTheme("nonexistent")
	if engine.Config().Theme.Name != "default" {
		t.Errorf("expected default for unknown theme, got %q", engine.Config().Theme.Name)
	}
}

func TestEngine_DescribeVariable(t *testing.T) {
	var out bytes.Buffer
	engine := NewEngine(nil, &out, nil)

	desc := engine.DescribeVariable("vulnerability")
	if desc == "" {
		t.Fatal("expected description for vulnerability")
	}

	// Should include fields
	if !strings.Contains(desc, "Fields:") {
		t.Error("expected 'Fields:' in description")
	}
}

func TestEngine_DescribeFunction(t *testing.T) {
	var out bytes.Buffer
	engine := NewEngine(nil, &out, nil)

	desc := engine.DescribeFunction("severityAtLeast")
	if desc == "" {
		t.Fatal("expected description for severityAtLeast")
	}

	// Should include signature
	if !strings.Contains(desc, "severityAtLeast") {
		t.Error("expected function name in description")
	}
}

func TestEngine_SimpleReadLine(t *testing.T) {
	input := "test input\n"
	in := strings.NewReader(input)
	var out bytes.Buffer
	engine := NewEngine(in, &out, nil)

	readLine := engine.SimpleReadLine()
	line, err := readLine(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if line != "test input" {
		t.Errorf("expected 'test input', got %q", line)
	}
}

func TestOutput_StyleCommandSyntax(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		contains []string
	}{
		{
			name:     "command with colon",
			input:    ":help",
			contains: []string{":help"},
		},
		{
			name:     "command with key=value",
			input:    ":set key=value",
			contains: []string{":set", "key", "=", "value"},
		},
		{
			name:     "command with uppercase placeholder",
			input:    ":entrypoint NAME",
			contains: []string{":entrypoint", "NAME"},
		},
		{
			name:     "command with optional bracket",
			input:    ":show [verbose]",
			contains: []string{":show", "[verbose]"},
		},
		{
			name:     "command with quoted literal",
			input:    `:example "test"`,
			contains: []string{":example", `"test"`},
		},
		{
			name:     "command with slash alternative",
			input:    ":exit/:quit/:q",
			contains: []string{":exit", "/", ":quit", "/", ":q"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			engine := NewEngine(nil, &out, nil)
			output := engine.Output()

			result := output.styleCommandSyntax(tt.input)

			// Result should contain all parts (with ANSI codes around them)
			for _, expected := range tt.contains {
				if !strings.Contains(result, expected) {
					t.Errorf("expected %q in styled output, got: %s", expected, result)
				}
			}
		})
	}
}

func TestOutput_StyledText(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		contains []string
	}{
		{
			name:     "text with command",
			input:    "Type :help for more info",
			contains: []string{"Type ", ":help", " for more info"},
		},
		{
			name:     "multiple commands",
			input:    "Use :example or :vuln to load data",
			contains: []string{":example", ":vuln"},
		},
		{
			name:     "plain text",
			input:    "No commands here",
			contains: []string{"No commands here"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			engine := NewEngine(nil, &out, nil)
			output := engine.Output()

			result := output.StyledText(tt.input)

			for _, expected := range tt.contains {
				if !strings.Contains(result, expected) {
					t.Errorf("expected %q in styled text, got: %s", expected, result)
				}
			}
		})
	}
}

func TestOutput_Hint(t *testing.T) {
	var out bytes.Buffer
	engine := NewEngine(nil, &out, nil)

	engine.Output().Hint("Type :help for commands, :example to load sample data")

	output := out.String()
	if !strings.Contains(output, ":help") {
		t.Errorf("expected :help in hint output, got: %s", output)
	}
	if !strings.Contains(output, ":example") {
		t.Errorf("expected :example in hint output, got: %s", output)
	}
	if !strings.Contains(output, "\n") {
		t.Error("expected hint to end with newline")
	}
}
