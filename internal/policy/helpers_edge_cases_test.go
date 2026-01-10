package policy

import "testing"

// TestHelperFunctions_EdgeCases tests edge cases for helper functions including
// nil inputs, empty values, and nested advisory structures.
func TestHelperFunctions_EdgeCases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    map[string]any
		expr     string
		expected any
	}{
		// Empty list edge cases
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
		// Nested advisory structure for vulnerabilitySeverity
		{
			name: "vulnerabilitySeverity_nested_advisory_severity",
			input: map[string]any{
				"vulnerability": map[string]any{
					"advisory": map[string]any{
						"severity": map[string]any{
							"level": int32(4), // CRITICAL
						},
					},
				},
			},
			expr:     "vulnerabilitySeverity(vulnerability)",
			expected: "CRITICAL",
		},
		{
			name: "vulnerabilitySeverity_nested_advisory_severity_high",
			input: map[string]any{
				"vulnerability": map[string]any{
					"advisory": map[string]any{
						"severity": map[string]any{
							"level": int32(3), // HIGH
						},
					},
				},
			},
			expr:     "vulnerabilitySeverity(vulnerability)",
			expected: "HIGH",
		},
		// vulnerabilityId field access (advisory_id is the main field)
		{
			name: "vulnerabilityId_advisory_id_field",
			input: map[string]any{
				"vulnerability": map[string]any{
					"advisory_id": "GHSA-1234-5678-abcd",
				},
			},
			expr:     "vulnerabilityId(vulnerability)",
			expected: "GHSA-1234-5678-abcd",
		},
		{
			name: "vulnerabilityId_id_field",
			input: map[string]any{
				"vulnerability": map[string]any{
					"id": "CVE-2024-9999",
				},
			},
			expr:     "vulnerabilityId(vulnerability)",
			expected: "CVE-2024-9999",
		},
		// hasFix checks fixedVersions field (uses []any internally)
		{
			name: "hasFix_fixedVersions_camelCase",
			input: map[string]any{
				"vulnerability": map[string]any{
					"fixedVersions": []any{"1.2.3"},
				},
			},
			expr:     "hasFix(vulnerability)",
			expected: true,
		},
		{
			name: "hasFix_fixed_versions_snake_case",
			input: map[string]any{
				"vulnerability": map[string]any{
					"fixed_versions": []any{"2.0.0"},
				},
			},
			expr:     "hasFix(vulnerability)",
			expected: true,
		},
		{
			name: "hasFix_empty_fixedVersions",
			input: map[string]any{
				"vulnerability": map[string]any{
					"fixedVersions": []any{},
				},
			},
			expr:     "hasFix(vulnerability)",
			expected: false,
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
		// Missing fields return safe defaults
		{
			name: "vulnerabilitySeverity_missing_returns_empty",
			input: map[string]any{
				"vulnerability": map[string]any{
					"id": "CVE-2024-1234", // No severity field
				},
			},
			expr:     "vulnerabilitySeverity(vulnerability)",
			expected: "",
		},
		{
			name: "vulnerabilityId_missing_returns_empty",
			input: map[string]any{
				"vulnerability": map[string]any{
					"severity": "HIGH", // No id field
				},
			},
			expr:     "vulnerabilityId(vulnerability)",
			expected: "",
		},
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
		// epssScore type coercion
		{
			name: "epssScore_float32",
			input: map[string]any{
				"vulnerability": map[string]any{
					"epss": float32(0.75),
				},
			},
			expr:     "epssScore(vulnerability) > 0.7",
			expected: true,
		},
		{
			name: "epssScore_int_coercion",
			input: map[string]any{
				"vulnerability": map[string]any{
					"epss": 1, // int instead of float
				},
			},
			expr:     "epssScore(vulnerability)",
			expected: float64(1),
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
