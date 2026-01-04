package policy

import (
	"testing"
	"time"
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
			result, err := Evaluate(t.Context(), tc.expr, nil)
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
			result, err := Evaluate(t.Context(), tc.expr, nil)
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

func TestPURLHelper_ViaEvaluate(t *testing.T) {
	tests := []struct {
		name     string
		expr     string
		expected bool
	}{
		{
			name:     "parse type",
			expr:     `purl("pkg:npm/left-pad@1.3.0").type == "npm"`,
			expected: true,
		},
		{
			name:     "parse qualifier",
			expr:     `purl("pkg:docker/library/alpine@3.19?platform=linux/amd64").qualifiers["platform"] == "linux/amd64"`,
			expected: true,
		},
		{
			name:     "invalid returns null",
			expr:     `purl("not-a-purl") == null`,
			expected: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := Evaluate(t.Context(), tc.expr, nil)
			if err != nil {
				t.Fatalf("Evaluate() error: %v", err)
			}
			got, ok := result.(bool)
			if !ok {
				t.Fatalf("expected bool result, got %T (%v)", result, result)
			}
			if got != tc.expected {
				t.Errorf("%s = %v, want %v", tc.expr, got, tc.expected)
			}
		})
	}
}

func TestNow_ViaEvaluate(t *testing.T) {
	// Test now() returns a timestamp
	result, err := Evaluate(t.Context(), `now()`, nil)
	if err != nil {
		t.Fatalf("Evaluate() error: %v", err)
	}
	// The result should be convertible to a time-like value
	if result == nil {
		t.Error("now() returned nil")
	}
}

func TestIntNow_ViaEvaluate(t *testing.T) {
	// Test that int(now()) works as the idiomatic way to get Unix timestamp
	result, err := Evaluate(t.Context(), `int(now())`, nil)
	if err != nil {
		t.Fatalf("Evaluate() error: %v", err)
	}
	unix, ok := result.(int64)
	if !ok {
		t.Fatalf("expected int64 result, got %T (%v)", result, result)
	}
	// Should be a reasonable Unix timestamp (after 2020)
	if unix < 1577836800 { // 2020-01-01
		t.Errorf("int(now()) = %d, expected Unix timestamp after 2020", unix)
	}
}

func TestAge_ViaEvaluate(t *testing.T) {
	// Test age with a Unix timestamp from the past (1 hour ago)
	// The age should be approximately 1 hour (3600 seconds)
	// Use int(now()) - the idiomatic way to get current Unix timestamp
	expr := `age(int(now()) - 3600) >= duration("59m")`
	result, err := Evaluate(t.Context(), expr, nil)
	if err != nil {
		t.Fatalf("Evaluate() error: %v", err)
	}
	got, ok := result.(bool)
	if !ok {
		t.Fatalf("expected bool result, got %T (%v)", result, result)
	}
	if !got {
		t.Error("expected age of 1-hour-old timestamp to be >= 59m")
	}
}

func TestTimestamp_ViaEvaluate(t *testing.T) {
	// Test CEL native timestamp(int) constructor
	// 1704067200 = 2024-01-01 00:00:00 UTC
	expr := `timestamp(1704067200) < now()`
	result, err := Evaluate(t.Context(), expr, nil)
	if err != nil {
		t.Fatalf("Evaluate() error: %v", err)
	}
	got, ok := result.(bool)
	if !ok {
		t.Fatalf("expected bool result, got %T (%v)", result, result)
	}
	if !got {
		t.Error("expected 2024-01-01 to be before now()")
	}
}

func TestTimeFunctions_JWTScenarios(t *testing.T) {
	nowUnix := time.Now().Unix()

	tests := []struct {
		name     string
		expr     string
		input    map[string]any
		expected bool
	}{
		{
			name: "token issued recently",
			expr: `age(jwt.iat) < duration("1h")`,
			input: map[string]any{
				"jwt": map[string]any{
					"iat": nowUnix - 1800, // 30 minutes ago
				},
			},
			expected: true,
		},
		{
			name: "token issued long ago",
			expr: `age(jwt.iat) > duration("1h")`,
			input: map[string]any{
				"jwt": map[string]any{
					"iat": nowUnix - 7200, // 2 hours ago
				},
			},
			expected: true,
		},
		{
			name: "token not expired using native timestamp",
			expr: `timestamp(jwt.exp) > now()`,
			input: map[string]any{
				"jwt": map[string]any{
					"exp": nowUnix + 3600, // 1 hour from now
				},
			},
			expected: true,
		},
		{
			name: "token expired using native timestamp",
			expr: `timestamp(jwt.exp) < now()`,
			input: map[string]any{
				"jwt": map[string]any{
					"exp": nowUnix - 3600, // 1 hour ago
				},
			},
			expected: true,
		},
		{
			name: "alternative age via subtraction",
			expr: `now() - timestamp(jwt.iat) > duration("30m")`,
			input: map[string]any{
				"jwt": map[string]any{
					"iat": nowUnix - 3600, // 1 hour ago
				},
			},
			expected: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := Evaluate(t.Context(), tc.expr, tc.input)
			if err != nil {
				t.Fatalf("Evaluate() error: %v", err)
			}
			got, ok := result.(bool)
			if !ok {
				t.Fatalf("expected bool result, got %T (%v)", result, result)
			}
			if got != tc.expected {
				t.Errorf("%s = %v, want %v", tc.expr, got, tc.expected)
			}
		})
	}
}

func TestMathExtensions_ViaEvaluate(t *testing.T) {

	tests := []struct {
		name     string
		expr     string
		expected any
	}{
		{
			name:     "math.abs positive",
			expr:     `math.abs(-5)`,
			expected: int64(5),
		},
		{
			name:     "math.abs negative input",
			expr:     `math.abs(-42)`,
			expected: int64(42),
		},
		{
			name:     "math.greatest",
			expr:     `math.greatest(1, 5, 3)`,
			expected: int64(5),
		},
		{
			name:     "math.least",
			expr:     `math.least(10, 5, 8)`,
			expected: int64(5),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := Evaluate(t.Context(), tc.expr, nil)
			if err != nil {
				t.Fatalf("Evaluate() error: %v", err)
			}
			if result != tc.expected {
				t.Errorf("%s = %v (%T), want %v (%T)", tc.expr, result, result, tc.expected, tc.expected)
			}
		})
	}
}

func TestBindings_ViaEvaluate(t *testing.T) {

	// Test cel.bind() for local variables
	expr := `cel.bind(threshold, 10, vulnerabilities.filter(v, v.score > threshold).size())`
	input := map[string]any{
		"vulnerabilities": []map[string]any{
			{"id": "CVE-1", "score": 5},
			{"id": "CVE-2", "score": 15},
			{"id": "CVE-3", "score": 8},
			{"id": "CVE-4", "score": 12},
		},
	}

	result, err := Evaluate(t.Context(), expr, input)
	if err != nil {
		t.Fatalf("Evaluate() error: %v", err)
	}
	got, ok := result.(int64)
	if !ok {
		t.Fatalf("expected int64 result, got %T (%v)", result, result)
	}
	if got != 2 { // CVE-2 (15) and CVE-4 (12) are > 10
		t.Errorf("expected 2 vulns above threshold, got %d", got)
	}
}

// ===== Container Image Helper Function Tests =====

func TestImageRef_ViaEvaluate(t *testing.T) {
	tests := []struct {
		name     string
		expr     string
		expected bool
	}{
		{
			name:     "parse registry from gcr.io",
			expr:     `imageRef("gcr.io/project/app:v1.2.3").registry == "gcr.io"`,
			expected: true,
		},
		{
			name:     "parse tag",
			expr:     `imageRef("nginx:1.24").tag == "1.24"`,
			expected: true,
		},
		{
			name:     "parse digest",
			expr:     `imageRef("alpine@sha256:abc123").digest == "sha256:abc123"`,
			expected: true,
		},
		{
			name:     "implicit docker.io for library images",
			expr:     `imageRef("nginx").registry == "docker.io"`,
			expected: true,
		},
		{
			name:     "implicit library namespace",
			expr:     `imageRef("nginx:latest").repository == "library/nginx"`,
			expected: true,
		},
		{
			name:     "user repo on docker.io",
			expr:     `imageRef("myuser/myapp:v1").registry == "docker.io"`,
			expected: true,
		},
		{
			name:     "ghcr.io registry",
			expr:     `imageRef("ghcr.io/owner/repo:tag").registry == "ghcr.io"`,
			expected: true,
		},
		{
			name:     "strip oci:// scheme",
			expr:     `imageRef("oci://nginx:1.24").tag == "1.24"`,
			expected: true,
		},
		{
			name:     "strip docker-daemon:// scheme",
			expr:     `imageRef("docker-daemon://nginx:1.24").registry == "docker.io"`,
			expected: true,
		},
		{
			name:     "parse name from nested path",
			expr:     `imageRef("gcr.io/google-containers/pause:3.1").name == "pause"`,
			expected: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := Evaluate(t.Context(), tc.expr, nil)
			if err != nil {
				t.Fatalf("Evaluate() error: %v", err)
			}
			got, ok := result.(bool)
			if !ok {
				t.Fatalf("expected bool result, got %T (%v)", result, result)
			}
			if got != tc.expected {
				t.Errorf("%s = %v, want %v", tc.expr, got, tc.expected)
			}
		})
	}
}

// TestImageRef_Composability demonstrates how imageRef() composes with native CEL
// to achieve the same functionality as the removed convenience functions.
func TestImageRef_Composability(t *testing.T) {
	tests := []struct {
		name     string
		expr     string
		expected bool
	}{
		// These show how to replace isLatestTag() with imageRef() + CEL
		{
			name:     "detect explicit latest (replaces isLatestTag)",
			expr:     `imageRef("nginx:latest").tag == "latest"`,
			expected: true,
		},
		{
			name:     "detect implicit latest (no tag, no digest)",
			expr:     `cel.bind(r, imageRef("nginx"), r.tag == "" && r.digest == "")`,
			expected: true,
		},
		{
			name:     "specific tag is not latest",
			expr:     `imageRef("nginx:1.24").tag == "latest"`,
			expected: false,
		},

		// These show how to replace hasDigest() with imageRef() + CEL
		{
			name:     "detect digest presence (replaces hasDigest)",
			expr:     `imageRef("nginx@sha256:abc123").digest != ""`,
			expected: true,
		},
		{
			name:     "tag-only has no digest",
			expr:     `imageRef("nginx:1.24").digest != ""`,
			expected: false,
		},

		// These show how to replace isSemverTag() with imageRef() + matches()
		{
			name:     "semver check with regex (replaces isSemverTag)",
			expr:     `imageRef("nginx:v1.2.3").tag.matches("^v?[0-9]+\\.[0-9]+\\.[0-9]+")`,
			expected: true,
		},
		{
			name:     "non-semver tag fails regex",
			expr:     `imageRef("nginx:latest").tag.matches("^v?[0-9]+\\.[0-9]+\\.[0-9]+")`,
			expected: false,
		},

		// These show how to replace registryMatches() with imageRef() + string functions
		{
			name:     "exact registry match (replaces registryMatches)",
			expr:     `imageRef("gcr.io/project/app:v1").registry == "gcr.io"`,
			expected: true,
		},
		{
			name:     "registry suffix match (replaces glob)",
			expr:     `imageRef("us.gcr.io/project/app:v1").registry.endsWith(".gcr.io")`,
			expected: true,
		},
		{
			name:     "registry in allowlist",
			expr:     `imageRef("ghcr.io/owner/repo:v1").registry in ["docker.io", "ghcr.io", "gcr.io"]`,
			expected: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := Evaluate(t.Context(), tc.expr, nil)
			if err != nil {
				t.Fatalf("Evaluate() error: %v", err)
			}
			got, ok := result.(bool)
			if !ok {
				t.Fatalf("expected bool result, got %T (%v)", result, result)
			}
			if got != tc.expected {
				t.Errorf("%s = %v, want %v", tc.expr, got, tc.expected)
			}
		})
	}
}

// TestBaseImage_ViaEvaluate tests the baseImage() function.
func TestBaseImage_ViaEvaluate(t *testing.T) {
	tests := []struct {
		name     string
		history  []map[string]any
		expected string
	}{
		{
			name: "simple FROM",
			history: []map[string]any{
				{"created_by": "FROM alpine:3.19"},
				{"created_by": "RUN apk add curl"},
			},
			expected: "alpine:3.19",
		},
		{
			name: "FROM with AS",
			history: []map[string]any{
				{"created_by": "FROM golang:1.21 AS builder"},
				{"created_by": "RUN go build"},
			},
			expected: "golang:1.21",
		},
		{
			name: "FROM with platform",
			history: []map[string]any{
				{"created_by": "FROM --platform=linux/amd64 ubuntu:22.04"},
			},
			expected: "ubuntu:22.04",
		},
		{
			name: "nop style FROM",
			history: []map[string]any{
				{"created_by": "/bin/sh -c #(nop) FROM gcr.io/distroless/static:nonroot"},
			},
			expected: "gcr.io/distroless/static:nonroot",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input := map[string]any{"history": tc.history}
			result, err := Evaluate(t.Context(), `baseImage(history)`, input)
			if err != nil {
				t.Fatalf("Evaluate() error: %v", err)
			}
			got, ok := result.(string)
			if !ok {
				t.Fatalf("expected string result, got %T (%v)", result, result)
			}
			if got != tc.expected {
				t.Errorf("baseImage() = %q, want %q", got, tc.expected)
			}
		})
	}
}

// TestBaseImage_Composability demonstrates how baseImage() composes with native CEL
// to achieve the same functionality as the removed convenience functions.
func TestBaseImage_Composability(t *testing.T) {
	tests := []struct {
		name     string
		history  []map[string]any
		expr     string
		expected bool
	}{
		// These show how to replace isDistrolessBase() with baseImage() + contains()
		{
			name: "detect distroless (replaces isDistrolessBase)",
			history: []map[string]any{
				{"created_by": "FROM gcr.io/distroless/static:nonroot"},
			},
			expr:     `baseImage(history).contains("distroless")`,
			expected: true,
		},
		{
			name: "detect chainguard",
			history: []map[string]any{
				{"created_by": "FROM cgr.dev/chainguard/static:latest"},
			},
			expr:     `baseImage(history).contains("chainguard")`,
			expected: true,
		},

		// These show how to replace isAlpineBase() with baseImage() + contains()
		{
			name: "detect alpine (replaces isAlpineBase)",
			history: []map[string]any{
				{"created_by": "FROM alpine:3.19"},
			},
			expr:     `baseImage(history).contains("alpine")`,
			expected: true,
		},
		{
			name: "detect alpine variant",
			history: []map[string]any{
				{"created_by": "FROM python:3.11-alpine"},
			},
			expr:     `baseImage(history).contains("alpine")`,
			expected: true,
		},

		// Complex composition: parse base image with imageRef()
		{
			name: "parse base image registry",
			history: []map[string]any{
				{"created_by": "FROM gcr.io/distroless/static:nonroot"},
			},
			expr:     `imageRef(baseImage(history)).registry == "gcr.io"`,
			expected: true,
		},

		// Checking minimal base images
		{
			name: "check for minimal base image",
			history: []map[string]any{
				{"created_by": "FROM alpine:3.19"},
			},
			expr:     `cel.bind(base, baseImage(history), base.contains("alpine") || base.contains("distroless") || base.contains("scratch"))`,
			expected: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input := map[string]any{"history": tc.history}
			result, err := Evaluate(t.Context(), tc.expr, input)
			if err != nil {
				t.Fatalf("Evaluate() error: %v", err)
			}
			got, ok := result.(bool)
			if !ok {
				t.Fatalf("expected bool result, got %T (%v)", result, result)
			}
			if got != tc.expected {
				t.Errorf("%s = %v, want %v", tc.expr, got, tc.expected)
			}
		})
	}
}

// TestNativeCEL_HistoryAnalysis demonstrates how to use native CEL
// for layer history analysis (replacing layerCommandContains, countLayers, etc.)
func TestNativeCEL_HistoryAnalysis(t *testing.T) {
	history := []map[string]any{
		{"created_by": "FROM alpine:3.19", "empty_layer": true},
		{"created_by": "RUN apk add --no-cache curl", "empty_layer": false},
		{"created_by": "ENV FOO=bar", "empty_layer": true},
		{"created_by": "COPY app /app", "empty_layer": false},
		{"created_by": "RUN pip install requests", "empty_layer": false},
	}

	tests := []struct {
		name     string
		expr     string
		expected any
	}{
		// Replacing layerCommandContains() with exists()
		{
			name:     "find curl with exists (replaces layerCommandContains)",
			expr:     `history.exists(h, h.created_by.contains("curl"))`,
			expected: true,
		},
		{
			name:     "find pip install",
			expr:     `history.exists(h, h.created_by.contains("pip install"))`,
			expected: true,
		},
		{
			name:     "pattern not found",
			expr:     `history.exists(h, h.created_by.contains("npm install"))`,
			expected: false,
		},

		// Replacing countLayers() with filter().size()
		{
			name:     "count non-empty layers (replaces countLayers)",
			expr:     `history.filter(h, !h.empty_layer).size()`,
			expected: int64(3),
		},

		// Secret detection with exists() and pattern matching
		{
			name:     "detect password pattern",
			expr:     `history.exists(h, h.created_by.contains("password="))`,
			expected: false,
		},

		// Multiple patterns with any/all
		{
			name:     "check for dangerous patterns",
			expr:     `history.exists(h, h.created_by.contains("curl") || h.created_by.contains("wget"))`,
			expected: true,
		},
	}

	input := map[string]any{"history": history}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := Evaluate(t.Context(), tc.expr, input)
			if err != nil {
				t.Fatalf("Evaluate() error: %v", err)
			}
			if result != tc.expected {
				t.Errorf("%s = %v (%T), want %v (%T)", tc.expr, result, result, tc.expected, tc.expected)
			}
		})
	}
}
