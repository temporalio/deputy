package policy

import "testing"

// TestHelperFunctions_EdgeCases tests edge cases for helper functions including
// nil inputs, empty values, and type coercion.
//
// Proto-first: Vulnerability field accessors (vulnerabilitySeverity, vulnerabilityId,
// hasFix, inKEV, epssScore) were removed in favor of direct proto field access.
// Use vulnerability.advisory_id, vulnerability.in_kev, vulnerability.epss,
// vulnerability.advisory.fixed_versions, vulnerability.advisory.severity.level
func TestHelperFunctions_EdgeCases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    map[string]any
		expr     string
		expected any
	}{
		// Path helper edge cases
		{
			name:     "pathLength_empty_list",
			input:    map[string]any{"path": []string{}},
			expr:     "pathLength(path)",
			expected: int64(0),
		},
		{
			name:     "pathDepth_empty_list_returns_zero",
			input:    map[string]any{"path": []string{}},
			expr:     "pathDepth(path)",
			expected: int64(0), // Empty path returns 0 (safe default)
		},
		{
			name:     "pathContains_empty_list",
			input:    map[string]any{"path": []string{}},
			expr:     `pathContains(path, "*")`,
			expected: false,
		},
		// Single element cases
		{
			name:     "pathLength_single_element",
			input:    map[string]any{"path": []string{"myapp"}},
			expr:     "pathLength(path)",
			expected: int64(1),
		},
		{
			name:     "pathDepth_single_element_is_direct",
			input:    map[string]any{"path": []string{"myapp"}},
			expr:     "pathDepth(path)",
			expected: int64(0), // Direct dependency
		},

		// Edge scope enumeration values (matches proto: 0=unspecified, 1=runtime, 2=dev, 3=optional, 4=build, 5=test)
		{
			name: "edgeScope_unspecified",
			input: map[string]any{
				"edge": map[string]any{"scope": int32(0)},
			},
			expr:     "edgeScope(edge)",
			expected: "unspecified",
		},
		{
			name: "edgeScope_runtime",
			input: map[string]any{
				"edge": map[string]any{"scope": int32(1)},
			},
			expr:     "edgeScope(edge)",
			expected: "runtime",
		},
		{
			name: "edgeScope_dev",
			input: map[string]any{
				"edge": map[string]any{"scope": int32(2)},
			},
			expr:     "edgeScope(edge)",
			expected: "dev",
		},
		{
			name: "edgeScope_optional",
			input: map[string]any{
				"edge": map[string]any{"scope": int32(3)},
			},
			expr:     "edgeScope(edge)",
			expected: "optional",
		},
		{
			name: "edgeScope_build",
			input: map[string]any{
				"edge": map[string]any{"scope": int32(4)},
			},
			expr:     "edgeScope(edge)",
			expected: "build",
		},
		{
			name: "edgeScope_test",
			input: map[string]any{
				"edge": map[string]any{"scope": int32(5)},
			},
			expr:     "edgeScope(edge)",
			expected: "test",
		},

		// Node helper edge cases
		{
			name: "nodePurl_missing_returns_empty",
			input: map[string]any{
				"node": map[string]any{
					"name": "lodash", // No purl field
				},
			},
			expr:     "nodePurl(node)",
			expected: "",
		},

		// Type coercion for numeric fields
		{
			name: "edgeScope_int64_coercion",
			input: map[string]any{
				"edge": map[string]any{"scope": int64(1)}, // int64 instead of int32
			},
			expr:     "edgeScope(edge)",
			expected: "runtime",
		},
		{
			name: "edgeScope_string_passthrough",
			input: map[string]any{
				"edge": map[string]any{"scope": "custom-scope"},
			},
			expr:     "edgeScope(edge)",
			expected: "custom-scope",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := Evaluate(t.Context(), tc.expr, tc.input)
			if err != nil {
				t.Fatalf("Evaluate() error: %v", err)
			}
			if result != tc.expected {
				t.Errorf("%s = %v (%T), want %v (%T)", tc.expr, result, result, tc.expected, tc.expected)
			}
		})
	}
}
