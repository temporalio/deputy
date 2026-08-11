package repl

import (
	"slices"
	"testing"

	"github.com/temporalio/deputy/internal/policy"
)

func TestNewSchemaRegistry(t *testing.T) {
	r := NewSchemaRegistry()

	// Should have registered variables
	vars := r.VariableNames()
	if len(vars) == 0 {
		t.Error("expected registered variables")
	}

	// Should have vulnerability schema
	vuln := r.GetVariable("vulnerability")
	if vuln == nil {
		t.Fatal("expected vulnerability schema")
	}
	if vuln.Description == "" {
		t.Error("expected vulnerability description")
	}

	// Should have fields from proto
	if len(vuln.Fields) == 0 {
		t.Error("expected vulnerability fields")
	}

	// Check specific field exists
	hasAdvisoryId := false
	for _, f := range vuln.Fields {
		if f.Name == "advisory_id" {
			hasAdvisoryId = true
			if f.CELName != "advisoryId" {
				t.Errorf("expected CEL name 'advisoryId', got %q", f.CELName)
			}
			if f.Type != "string" {
				t.Errorf("expected type 'string', got %q", f.Type)
			}
			break
		}
	}
	if !hasAdvisoryId {
		t.Error("expected advisory_id field in vulnerability")
	}
}

func TestSchemaRegistry_Enums(t *testing.T) {
	r := NewSchemaRegistry()

	// Should have severity enum
	severity := r.GetEnum("severity")
	if severity == nil {
		t.Fatal("expected severity enum")
	}

	if severity.Name != "SeverityLevel" {
		t.Errorf("expected name 'SeverityLevel', got %q", severity.Name)
	}

	if len(severity.Values) != 5 {
		t.Errorf("expected 5 severity values, got %d", len(severity.Values))
	}

	// Check critical value (constant members are lowercase at runtime)
	hasCritical := false
	for _, v := range severity.Values {
		if v.Name == "critical" {
			hasCritical = true
			if v.Number != 4 {
				t.Errorf("expected critical number 4, got %d", v.Number)
			}
			break
		}
	}
	if !hasCritical {
		t.Error("expected critical in severity enum")
	}

	// The offered member names must match the runtime constants map exactly,
	// otherwise completions teach identifiers that fail to evaluate.
	var names []string
	for _, v := range severity.Values {
		names = append(names, v.Name)
	}
	if want := policy.SeverityConstantNames(); !slices.Equal(names, want) {
		t.Errorf("severity enum members = %v, want runtime constants %v", names, want)
	}

	// Should have scope enum
	scope := r.GetEnum("scope")
	if scope == nil {
		t.Fatal("expected scope enum")
	}
}

// TestSchemaRegistry_EnumDescriptionsComeFromProtoComments pins the enum member
// descriptions to the proto comments. Every member must carry a description,
// because an empty one means the descriptor lookup drifted (a renamed or
// renumbered enum value) rather than that the member deserves no help text. The
// exact expectations keep the assertion non-vacuous: they are the proto comments
// verbatim, first sentence and trailing period included, so editing a comment in
// the .proto surfaces here instead of silently changing REPL hints.
func TestSchemaRegistry_EnumDescriptionsComeFromProtoComments(t *testing.T) {
	r := NewSchemaRegistry()

	tests := []struct {
		enum string
		want map[string]string // member name -> exact expected description
	}{
		{
			enum: "severity",
			want: map[string]string{
				"critical":    "Critical severity (CVSS 9.0-10.0).",
				"unspecified": "The advisory record Deputy matched carries no rating.",
			},
		},
		{
			enum: "scope",
			want: map[string]string{
				"RUNTIME": "Runtime dependency.",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.enum, func(t *testing.T) {
			schema := r.GetEnum(tt.enum)
			if schema == nil {
				t.Fatalf("expected %s enum", tt.enum)
			}
			if len(schema.Values) == 0 {
				t.Fatalf("expected %s enum members", tt.enum)
			}
			for _, v := range schema.Values {
				if v.Description == "" {
					t.Errorf("%s.%s has an empty description: the proto comment is missing or the descriptor lookup no longer resolves this member", tt.enum, v.Name)
				}
				if want, ok := tt.want[v.Name]; ok && v.Description != want {
					t.Errorf("%s.%s description = %q, want the proto comment %q", tt.enum, v.Name, v.Description, want)
				}
			}
			// Guard the expectations themselves: a renamed member would make
			// the exact checks above vacuous.
			for name := range tt.want {
				if !slices.ContainsFunc(schema.Values, func(v EnumValue) bool { return v.Name == name }) {
					t.Errorf("%s enum has no member %q to check", tt.enum, name)
				}
			}
		})
	}
}

func TestSchemaRegistry_Functions(t *testing.T) {
	r := NewSchemaRegistry()

	funcs := r.GetFunctions()
	if len(funcs) == 0 {
		t.Fatal("expected registered functions")
	}

	// Check for specific function
	var severityAtLeast *FunctionSchema
	for i := range funcs {
		if funcs[i].Name == "severityAtLeast" {
			severityAtLeast = &funcs[i]
			break
		}
	}

	if severityAtLeast == nil {
		t.Fatal("expected severityAtLeast function")
	}

	if severityAtLeast.Category != "severity" {
		t.Errorf("expected category 'severity', got %q", severityAtLeast.Category)
	}

	if severityAtLeast.ReturnType != "bool" {
		t.Errorf("expected return type 'bool', got %q", severityAtLeast.ReturnType)
	}
}

func TestSchemaRegistry_FunctionsByCategory(t *testing.T) {
	r := NewSchemaRegistry()

	severityFuncs := r.GetFunctionsByCategory("severity")
	if len(severityFuncs) < 3 {
		t.Errorf("expected at least 3 severity functions, got %d", len(severityFuncs))
	}

	graphFuncs := r.GetFunctionsByCategory("graph")
	if len(graphFuncs) < 5 {
		t.Errorf("expected at least 5 graph functions, got %d", len(graphFuncs))
	}
}

func TestSchemaRegistry_GraphSchema(t *testing.T) {
	r := NewSchemaRegistry()

	node := r.GetVariable("node")
	if node == nil {
		t.Fatal("expected node schema")
	}

	// Check for expected fields
	expectedFields := []string{"purl", "name", "version", "ecosystem", "direct", "depth"}
	for _, expected := range expectedFields {
		found := false
		for _, f := range node.Fields {
			if f.Name == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected field %q in node schema", expected)
		}
	}

	stats := r.GetVariable("stats")
	if stats == nil {
		t.Fatal("expected stats schema")
	}
}

func TestFieldSchema_FormatFieldType(t *testing.T) {
	tests := []struct {
		name     string
		field    *FieldSchema
		expected string
	}{
		{
			name:     "simple string",
			field:    &FieldSchema{Type: "string"},
			expected: "string",
		},
		{
			name:     "repeated string",
			field:    &FieldSchema{Type: "string", Repeated: true},
			expected: "list<string>",
		},
		{
			name:     "optional int",
			field:    &FieldSchema{Type: "int", Optional: true},
			expected: "int?",
		},
		{
			name:     "message type",
			field:    &FieldSchema{Type: "message", MessageType: "Advisory"},
			expected: "Advisory",
		},
		{
			name:     "map type",
			field:    &FieldSchema{Type: "map", MapKey: "string", MapValue: "string"},
			expected: "map<string, string>",
		},
		{
			name:     "repeated message",
			field:    &FieldSchema{Type: "message", MessageType: "Finding", Repeated: true},
			expected: "list<Finding>",
		},
		{
			name:     "enum type",
			field:    &FieldSchema{Type: "enum", EnumType: "SeverityLevel"},
			expected: "SeverityLevel",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.field.FormatFieldType()
			if got != tt.expected {
				t.Errorf("FormatFieldType() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestToCamelCase(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"advisory_id", "advisoryId"},
		{"fixed_versions", "fixedVersions"},
		{"name", "name"},
		{"in_kev", "inKev"},
		{"kev_date_added", "kevDateAdded"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := toCamelCase(tt.input)
			if got != tt.expected {
				t.Errorf("toCamelCase(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

// TestSchemaFunctions_SeverityHelpersAreRegistered pins the severity helper
// functions offered in completions to the runtime helper catalog, so the REPL
// cannot offer functions (e.g. a former vulnerabilitySeverity entry) that are
// not registered in any CEL environment.
func TestSchemaFunctions_SeverityHelpersAreRegistered(t *testing.T) {
	registered := make(map[string]bool)
	for _, fn := range policy.HelperCatalog() {
		registered[fn.Name] = true
	}

	r := NewSchemaRegistry()
	for _, fn := range r.GetFunctionsByCategory("severity") {
		if !registered[fn.Name] {
			t.Errorf("schema offers severity function %q, which is not in the runtime helper catalog", fn.Name)
		}
	}
}
