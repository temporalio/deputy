package security

import (
	"slices"
	"testing"
)

func TestIsSensitiveEnvName(t *testing.T) {
	tests := []struct {
		name     string
		envName  string
		expected bool
	}{
		{"empty", "", false},
		{"plain var", "PATH", false},
		{"plain var lowercase", "path", false},
		{"home", "HOME", false},
		{"password", "PASSWORD", true},
		{"password lowercase", "password", true},
		{"db password", "DB_PASSWORD", true},
		{"api key", "API_KEY", true},
		{"apikey", "APIKEY", true},
		{"secret", "SECRET", true},
		{"aws secret", "AWS_SECRET", true},
		{"github token", "GITHUB_TOKEN", true},
		{"token", "TOKEN", true},
		{"auth token", "AUTH_TOKEN", true},
		{"private key", "PRIVATE_KEY", true},
		{"credentials", "CREDENTIALS", true},
		{"credential", "CREDENTIAL", true},
		{"database url", "DATABASE_URL", true},
		{"connection string", "CONNECTION_STRING", true},
		{"access key", "ACCESS_KEY", true},
		{"mixed case token", "MyAuthToken", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsSensitiveEnvName(tt.envName)
			if got != tt.expected {
				t.Errorf("IsSensitiveEnvName(%q) = %v, want %v", tt.envName, got, tt.expected)
			}
		})
	}
}

func TestDetectSensitiveEnvNames(t *testing.T) {
	tests := []struct {
		name     string
		envVars  map[string]string
		expected []string
	}{
		{
			name:     "nil map",
			envVars:  nil,
			expected: nil,
		},
		{
			name:     "empty map",
			envVars:  map[string]string{},
			expected: nil,
		},
		{
			name: "no sensitive vars",
			envVars: map[string]string{
				"PATH": "/usr/bin",
				"HOME": "/home/user",
			},
			expected: nil,
		},
		{
			name: "single sensitive var",
			envVars: map[string]string{
				"PATH":         "/usr/bin",
				"DATABASE_URL": "postgres://...",
			},
			expected: []string{"DATABASE_URL"},
		},
		{
			name: "multiple sensitive vars",
			envVars: map[string]string{
				"PATH":         "/usr/bin",
				"DB_PASSWORD":  "secret123",
				"API_KEY":      "key123",
				"GITHUB_TOKEN": "ghp_xxx",
			},
			expected: []string{"DB_PASSWORD", "API_KEY", "GITHUB_TOKEN"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectSensitiveEnvNames(tt.envVars)

			// Sort both for comparison since map iteration is non-deterministic
			slices.Sort(got)
			expected := tt.expected
			slices.Sort(expected)

			if len(got) != len(expected) {
				t.Errorf("DetectSensitiveEnvNames() returned %d items, want %d", len(got), len(expected))
				t.Errorf("got: %v, want: %v", got, expected)
				return
			}
			for i := range got {
				if got[i] != expected[i] {
					t.Errorf("DetectSensitiveEnvNames()[%d] = %q, want %q", i, got[i], expected[i])
				}
			}
		})
	}
}

func TestDetectSensitiveEnvFromList(t *testing.T) {
	tests := []struct {
		name     string
		envList  []string
		expected []string
	}{
		{
			name:     "nil list",
			envList:  nil,
			expected: nil,
		},
		{
			name:     "empty list",
			envList:  []string{},
			expected: nil,
		},
		{
			name: "no sensitive vars",
			envList: []string{
				"PATH=/usr/bin",
				"HOME=/home/user",
			},
			expected: nil,
		},
		{
			name: "single sensitive var",
			envList: []string{
				"PATH=/usr/bin",
				"DATABASE_URL=postgres://localhost/db",
			},
			expected: []string{"DATABASE_URL"},
		},
		{
			name: "multiple sensitive vars",
			envList: []string{
				"PATH=/usr/bin",
				"DB_PASSWORD=secret123",
				"API_KEY=key123",
				"GITHUB_TOKEN=ghp_xxx",
			},
			expected: []string{"DB_PASSWORD", "API_KEY", "GITHUB_TOKEN"},
		},
		{
			name: "vars without values",
			envList: []string{
				"PATH=/usr/bin",
				"API_KEY",
			},
			expected: []string{"API_KEY"},
		},
		{
			name: "empty value",
			envList: []string{
				"API_KEY=",
			},
			expected: []string{"API_KEY"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectSensitiveEnvFromList(tt.envList)

			if len(got) != len(tt.expected) {
				t.Errorf("DetectSensitiveEnvFromList() returned %d items, want %d", len(got), len(tt.expected))
				t.Errorf("got: %v, want: %v", got, tt.expected)
				return
			}
			for i := range got {
				if got[i] != tt.expected[i] {
					t.Errorf("DetectSensitiveEnvFromList()[%d] = %q, want %q", i, got[i], tt.expected[i])
				}
			}
		})
	}
}
