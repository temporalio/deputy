package repl

import (
	"testing"
)

func TestCompletionEngine_RootContext(t *testing.T) {
	schema := NewSchemaRegistry()
	engine := NewCompletionEngine(schema)

	// Empty input should return variables, enums, functions, keywords
	completions := engine.Complete("", 0)
	if len(completions) == 0 {
		t.Fatal("expected completions for empty input")
	}

	// Check we have different kinds
	kinds := make(map[CompletionKind]bool)
	for _, c := range completions {
		kinds[c.Kind] = true
	}

	if !kinds[CompletionVariable] {
		t.Error("expected variable completions")
	}
	if !kinds[CompletionFunction] {
		t.Error("expected function completions")
	}
	if !kinds[CompletionEnum] {
		t.Error("expected enum completions")
	}
}

func TestCompletionEngine_PartialMatch(t *testing.T) {
	schema := NewSchemaRegistry()
	engine := NewCompletionEngine(schema)

	// Partial "vul" should match "vulnerability"
	completions := engine.Complete("vul", 3)

	found := false
	for _, c := range completions {
		if c.Text == "vulnerability" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'vulnerability' in completions for 'vul'")
	}
}

func TestCompletionEngine_PartialRequest(t *testing.T) {
	schema := NewSchemaRegistry()
	engine := NewCompletionEngine(schema)

	// Partial "req" should match "request"
	completions := engine.Complete("req", 3)
	t.Logf("Completions for 'req': %d", len(completions))
	for _, c := range completions {
		t.Logf("  %s %s", c.Kind, c.Text)
	}

	found := false
	for _, c := range completions {
		if c.Text == "request" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'request' in completions for 'req'")
	}
}

func TestCompletionEngine_RequestFieldAccess(t *testing.T) {
	schema := NewSchemaRegistry()
	engine := NewCompletionEngine(schema)

	// "request." should return request fields
	completions := engine.Complete("request.", 8)
	if len(completions) == 0 {
		t.Fatal("expected field completions for 'request.'")
	}

	// All should be field kind
	for _, c := range completions {
		if c.Kind != CompletionField {
			t.Errorf("expected CompletionField, got %v for %q", c.Kind, c.Text)
		}
	}

	// Should include ecosystem
	foundEcosystem := false
	foundPackage := false
	for _, c := range completions {
		if c.Text == "ecosystem" {
			foundEcosystem = true
		}
		if c.Text == "package" {
			foundPackage = true
		}
	}
	if !foundEcosystem {
		t.Error("expected 'ecosystem' in request field completions")
	}
	if !foundPackage {
		t.Error("expected 'package' in request field completions")
	}
}

func TestCompletionEngine_FieldAccess(t *testing.T) {
	schema := NewSchemaRegistry()
	engine := NewCompletionEngine(schema)

	// "vulnerability." should return field completions
	completions := engine.Complete("vulnerability.", 14)
	if len(completions) == 0 {
		t.Fatal("expected field completions for 'vulnerability.'")
	}

	// All should be field kind
	for _, c := range completions {
		if c.Kind != CompletionField {
			t.Errorf("expected CompletionField, got %v for %q", c.Kind, c.Text)
		}
	}

	// Should include advisoryId
	found := false
	for _, c := range completions {
		if c.Text == "advisoryId" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'advisoryId' in vulnerability field completions")
	}
}

func TestCompletionEngine_PartialFieldAccess(t *testing.T) {
	schema := NewSchemaRegistry()
	engine := NewCompletionEngine(schema)

	// "vulnerability.adv" should filter to advisory-related fields
	completions := engine.Complete("vulnerability.adv", 17)

	for _, c := range completions {
		if c.Text != "advisoryId" && c.Text != "advisory" {
			t.Errorf("unexpected completion %q for 'vulnerability.adv'", c.Text)
		}
	}
}

func TestCompletionEngine_EnumAccess(t *testing.T) {
	schema := NewSchemaRegistry()
	engine := NewCompletionEngine(schema)

	// "severity." should return enum values
	completions := engine.Complete("severity.", 9)
	if len(completions) == 0 {
		t.Fatal("expected enum completions for 'severity.'")
	}

	// Should include CRITICAL
	found := false
	for _, c := range completions {
		if c.Text == "CRITICAL" {
			found = true
			if c.Kind != CompletionEnum {
				t.Errorf("expected CompletionEnum for CRITICAL, got %v", c.Kind)
			}
			break
		}
	}
	if !found {
		t.Error("expected 'CRITICAL' in severity enum completions")
	}
}

func TestCompletionEngine_PartialEnum(t *testing.T) {
	schema := NewSchemaRegistry()
	engine := NewCompletionEngine(schema)

	// "severity.HI" should filter to HIGH
	completions := engine.Complete("severity.HI", 11)

	if len(completions) != 1 {
		t.Errorf("expected 1 completion for 'severity.HI', got %d", len(completions))
	}
	if len(completions) > 0 && completions[0].Text != "HIGH" {
		t.Errorf("expected 'HIGH', got %q", completions[0].Text)
	}
}

func TestCompletionEngine_FunctionContext(t *testing.T) {
	schema := NewSchemaRegistry()
	engine := NewCompletionEngine(schema)

	// "severityAtLeast(" should return variables suitable as arguments
	completions := engine.Complete("severityAtLeast(", 16)

	// Should include vulnerability as a valid argument
	found := false
	for _, c := range completions {
		if c.Text == "vulnerability" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'vulnerability' as function argument completion")
	}
}

func TestCompletionEngine_Scoring(t *testing.T) {
	schema := NewSchemaRegistry()
	engine := NewCompletionEngine(schema)

	// Exact prefix match should score higher
	completions := engine.Complete("sev", 3)

	// Find severity and severityAtLeast
	var severityScore, severityAtLeastScore int
	for _, c := range completions {
		if c.Text == "severity" {
			severityScore = c.Score
		}
		if c.Text == "severityAtLeast" {
			severityAtLeastScore = c.Score
		}
	}

	// Both should have scores
	if severityScore == 0 {
		t.Error("expected non-zero score for 'severity'")
	}
	if severityAtLeastScore == 0 {
		t.Error("expected non-zero score for 'severityAtLeast'")
	}

	// Shorter match should score higher
	if severityScore < severityAtLeastScore {
		t.Error("expected 'severity' to score higher than 'severityAtLeast'")
	}
}

func TestCompletionEngine_GetHint_FieldType(t *testing.T) {
	schema := NewSchemaRegistry()
	engine := NewCompletionEngine(schema)

	// Hint for partial field should show type
	hint := engine.GetHint("vulnerability.adv", 17)
	if hint == nil {
		t.Fatal("expected hint for 'vulnerability.adv'")
	}
	// Hint text should contain type information
	if hint.Text == "" {
		t.Error("expected non-empty hint text")
	}
}

func TestCompletionEngine_GetHint_EnumDescription(t *testing.T) {
	schema := NewSchemaRegistry()
	engine := NewCompletionEngine(schema)

	// Hint for enum value should show description
	hint := engine.GetHint("severity.CRIT", 14)
	if hint == nil {
		t.Fatal("expected hint for 'severity.CRIT'")
	}
	if hint.Text == "" {
		t.Error("expected hint with description")
	}
}

func TestCompletionEngine_GetHint_GhostText(t *testing.T) {
	schema := NewSchemaRegistry()
	engine := NewCompletionEngine(schema)

	// Ghost text for partial root completion
	hint := engine.GetHint("vulner", 6)
	if hint == nil {
		t.Fatal("expected ghost text hint for 'vulner'")
	}
	if hint.Style != "ghost" {
		t.Errorf("expected ghost style, got %q", hint.Style)
	}
	// Should complete "ability"
	if hint.Text != "ability" {
		t.Errorf("expected hint 'ability', got %q", hint.Text)
	}
}

func TestCompletionEngine_DescribeVariable(t *testing.T) {
	schema := NewSchemaRegistry()
	engine := NewCompletionEngine(schema)

	desc := engine.DescribeVariable("vulnerability")
	if desc == "" {
		t.Fatal("expected description for vulnerability")
	}

	// Should contain field list
	if len(desc) < 100 {
		t.Error("expected detailed description with fields")
	}
}

func TestCompletionEngine_DescribeFunction(t *testing.T) {
	schema := NewSchemaRegistry()
	engine := NewCompletionEngine(schema)

	desc := engine.DescribeFunction("severityAtLeast")
	if desc == "" {
		t.Fatal("expected description for severityAtLeast")
	}

	// Should contain signature
	if len(desc) < 20 {
		t.Error("expected description with signature")
	}
}

func TestCompletionKind_Symbol(t *testing.T) {
	tests := []struct {
		kind   CompletionKind
		symbol string
	}{
		{CompletionVariable, "•"},
		{CompletionField, "·"},
		{CompletionFunction, "ƒ"},
		{CompletionEnum, "▪"},
		{CompletionKeyword, "◇"},
		{CompletionOperator, "∘"},
	}

	for _, tt := range tests {
		t.Run(tt.kind.String(), func(t *testing.T) {
			got := tt.kind.Symbol()
			if got != tt.symbol {
				t.Errorf("Symbol() = %q, want %q", got, tt.symbol)
			}
		})
	}
}

func TestCompletionKind_String(t *testing.T) {
	tests := []struct {
		kind CompletionKind
		str  string
	}{
		{CompletionVariable, "var"},
		{CompletionField, "field"},
		{CompletionFunction, "func"},
		{CompletionEnum, "enum"},
		{CompletionKeyword, "keyword"},
		{CompletionOperator, "op"},
	}

	for _, tt := range tests {
		t.Run(tt.str, func(t *testing.T) {
			got := tt.kind.String()
			if got != tt.str {
				t.Errorf("String() = %q, want %q", got, tt.str)
			}
		})
	}
}
