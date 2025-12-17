package policy

import (
	"context"
	"testing"
)

func TestLevenshtein(t *testing.T) {
	tests := []struct {
		name     string
		a        string
		b        string
		maxLen   int
		limit    int64
		expected int64
	}{
		{
			name:     "identical strings",
			a:        "hello",
			b:        "hello",
			maxLen:   128,
			limit:    -1,
			expected: 0,
		},
		{
			name:     "single char difference",
			a:        "hello",
			b:        "hallo",
			maxLen:   128,
			limit:    -1,
			expected: 1,
		},
		{
			name:     "completely different",
			a:        "abc",
			b:        "xyz",
			maxLen:   128,
			limit:    -1,
			expected: 3,
		},
		{
			name:     "empty first string",
			a:        "",
			b:        "hello",
			maxLen:   128,
			limit:    -1,
			expected: 5,
		},
		{
			name:     "empty second string",
			a:        "hello",
			b:        "",
			maxLen:   128,
			limit:    -1,
			expected: 5,
		},
		{
			name:     "both empty",
			a:        "",
			b:        "",
			maxLen:   128,
			limit:    -1,
			expected: 0,
		},
		{
			name:     "insertion",
			a:        "kitten",
			b:        "kittens",
			maxLen:   128,
			limit:    -1,
			expected: 1,
		},
		{
			name:     "deletion",
			a:        "sitting",
			b:        "sittin",
			maxLen:   128,
			limit:    -1,
			expected: 1,
		},
		{
			name:     "classic kitten-sitting example",
			a:        "kitten",
			b:        "sitting",
			maxLen:   128,
			limit:    -1,
			expected: 3,
		},
		{
			name:     "exceeds maxLen",
			a:        "this is a very long string that exceeds the maximum",
			b:        "short",
			maxLen:   10,
			limit:    -1,
			expected: -1,
		},
		{
			name:     "maxLen disabled",
			a:        "this is a very long string",
			b:        "short",
			maxLen:   0,
			limit:    -1,
			expected: 23, // actual distance
		},
		{
			name:     "early exit with limit",
			a:        "abcdefghij",
			b:        "klmnopqrst",
			maxLen:   128,
			limit:    5,
			expected: 6, // returns early when min row exceeds limit
		},
		{
			name:     "within limit",
			a:        "hello",
			b:        "hallo",
			maxLen:   128,
			limit:    2,
			expected: 1,
		},
		{
			name:     "case sensitive",
			a:        "Hello",
			b:        "hello",
			maxLen:   128,
			limit:    -1,
			expected: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := levenshtein(tc.a, tc.b, tc.maxLen, tc.limit)
			if result != tc.expected {
				t.Errorf("levenshtein(%q, %q, %d, %d) = %d, want %d",
					tc.a, tc.b, tc.maxLen, tc.limit, result, tc.expected)
			}
		})
	}
}

func TestLevenshtein_Symmetry(t *testing.T) {
	// Levenshtein distance should be symmetric: d(a,b) == d(b,a)
	pairs := [][2]string{
		{"hello", "world"},
		{"abc", "xyz"},
		{"kitten", "sitting"},
		{"", "test"},
		{"same", "same"},
	}

	for _, pair := range pairs {
		a, b := pair[0], pair[1]
		d1 := levenshtein(a, b, 128, -1)
		d2 := levenshtein(b, a, 128, -1)
		if d1 != d2 {
			t.Errorf("levenshtein not symmetric: d(%q,%q)=%d != d(%q,%q)=%d",
				a, b, d1, b, a, d2)
		}
	}
}

func TestLevenshteinWithin_ViaEvaluate(t *testing.T) {
	// Test the CEL function through actual evaluation
	ctx := context.Background()
	tests := []struct {
		name     string
		expr     string
		expected bool
	}{
		{
			name:     "exact match within 0",
			expr:     `levenshteinWithin("hello", "hello", 0)`,
			expected: true,
		},
		{
			name:     "one char diff within 1",
			expr:     `levenshteinWithin("hello", "hallo", 1)`,
			expected: true,
		},
		{
			name:     "one char diff not within 0",
			expr:     `levenshteinWithin("hello", "hallo", 0)`,
			expected: false,
		},
		{
			name:     "completely different not within 2",
			expr:     `levenshteinWithin("abc", "xyz", 2)`,
			expected: false,
		},
		{
			name:     "completely different within 3",
			expr:     `levenshteinWithin("abc", "xyz", 3)`,
			expected: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := Evaluate(ctx, tc.expr, nil)
			if err != nil {
				t.Fatalf("Evaluate() error: %v", err)
			}
			got, ok := result.(bool)
			if !ok {
				t.Fatalf("expected bool result, got %T", result)
			}
			if got != tc.expected {
				t.Errorf("%s = %v, want %v", tc.expr, got, tc.expected)
			}
		})
	}
}

func TestLevenshtein_ViaEvaluate(t *testing.T) {
	// Test the CEL function through actual evaluation
	ctx := context.Background()
	tests := []struct {
		name     string
		expr     string
		expected int64
	}{
		{
			name:     "exact match",
			expr:     `levenshtein("hello", "hello")`,
			expected: 0,
		},
		{
			name:     "one char diff",
			expr:     `levenshtein("hello", "hallo")`,
			expected: 1,
		},
		{
			name:     "kitten sitting",
			expr:     `levenshtein("kitten", "sitting")`,
			expected: 3,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := Evaluate(ctx, tc.expr, nil)
			if err != nil {
				t.Fatalf("Evaluate() error: %v", err)
			}
			got, ok := result.(int64)
			if !ok {
				t.Fatalf("expected int64 result, got %T (%v)", result, result)
			}
			if got != tc.expected {
				t.Errorf("%s = %d, want %d", tc.expr, got, tc.expected)
			}
		})
	}
}

func TestMinInt64(t *testing.T) {
	tests := []struct {
		name     string
		vals     []int64
		expected int64
	}{
		{
			name:     "single value",
			vals:     []int64{5},
			expected: 5,
		},
		{
			name:     "two values, first smaller",
			vals:     []int64{3, 7},
			expected: 3,
		},
		{
			name:     "two values, second smaller",
			vals:     []int64{7, 3},
			expected: 3,
		},
		{
			name:     "three values",
			vals:     []int64{5, 2, 8},
			expected: 2,
		},
		{
			name:     "negative values",
			vals:     []int64{-1, -5, 3},
			expected: -5,
		},
		{
			name:     "all same",
			vals:     []int64{4, 4, 4},
			expected: 4,
		},
		{
			name:     "empty slice",
			vals:     []int64{},
			expected: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := minInt64(tc.vals...)
			if result != tc.expected {
				t.Errorf("minInt64(%v) = %d, want %d", tc.vals, result, tc.expected)
			}
		})
	}
}
