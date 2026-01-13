package remediation

import (
	"testing"
)

func TestEcosystemNetworkProfiles(t *testing.T) {
	// Verify all expected ecosystems have profiles
	expectedEcosystems := []string{
		"go", "npm", "yarn", "pnpm",
		"pip", "poetry", "pipenv", "uv",
		"cargo", "gem", "bundler",
		"composer", "maven", "gradle",
		"nuget", "dotnet", "hex", "mix",
		"pub", "dart", "cocoapods", "conan",
	}

	for _, eco := range expectedEcosystems {
		profile, ok := EcosystemNetworkProfiles[eco]
		if !ok {
			t.Errorf("missing network profile for ecosystem %q", eco)
			continue
		}
		if len(profile) == 0 {
			t.Errorf("empty network profile for ecosystem %q", eco)
		}

		// Verify all endpoints have port numbers
		for _, endpoint := range profile {
			if !hasPort(endpoint) {
				t.Errorf("ecosystem %q endpoint %q missing port", eco, endpoint)
			}
		}
	}
}

func TestEcosystemImages(t *testing.T) {
	// Verify container-friendly ecosystems have images
	containerEcosystems := []string{
		"go", "npm", "yarn", "pnpm",
		"pip", "poetry", "pipenv", "uv",
		"cargo", "gem", "bundler",
		"composer", "maven", "gradle",
		"nuget", "dotnet",
	}

	for _, eco := range containerEcosystems {
		image, ok := EcosystemImages[eco]
		if !ok {
			t.Errorf("missing image for ecosystem %q", eco)
			continue
		}
		if image == "" {
			t.Errorf("empty image for ecosystem %q", eco)
		}
	}
}

func TestParseRuntime(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
	}{
		{"", false},
		{"docker", false},
		{"Docker", false},
		{"DOCKER", false},
		{"gvisor", false},
		{"none", false},
		{"sandbox-exec", false},
		{"sandboxexec", false},
		{"plugin", false},
		{"invalid", true},
		{"podman", true}, // Not implemented yet
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			_, err := parseRuntime(tc.input)
			if (err != nil) != tc.wantErr {
				t.Errorf("parseRuntime(%q) error = %v, wantErr = %v", tc.input, err, tc.wantErr)
			}
		})
	}
}

func TestParseMode(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
	}{
		{"", false},
		{"workspace-write", false},
		{"rw", false},
		{"read-only", false},
		{"ro", false},
		{"full-access", false},
		{"ephemeral", false},
		{"invalid", true},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			_, err := parseMode(tc.input)
			if (err != nil) != tc.wantErr {
				t.Errorf("parseMode(%q) error = %v, wantErr = %v", tc.input, err, tc.wantErr)
			}
		})
	}
}

func TestParseNetworkMode(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
	}{
		{"", false},
		{"allowlist", false},
		{"none", false},
		{"bridge", false},
		{"host", false},
		{"invalid", true},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			_, err := parseNetworkMode(tc.input)
			if (err != nil) != tc.wantErr {
				t.Errorf("parseNetworkMode(%q) error = %v, wantErr = %v", tc.input, err, tc.wantErr)
			}
		})
	}
}

func TestParseDuration(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
	}{
		{"30s", false},
		{"5m", false},
		{"1h", false},
		{"2h30m", false},
		{"invalid", true},
		{"", true},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			_, err := parseDuration(tc.input)
			if (err != nil) != tc.wantErr {
				t.Errorf("parseDuration(%q) error = %v, wantErr = %v", tc.input, err, tc.wantErr)
			}
		})
	}
}

func hasPort(endpoint string) bool {
	// Check if endpoint contains a port (host:port format)
	for i := len(endpoint) - 1; i >= 0; i-- {
		if endpoint[i] == ':' {
			return i < len(endpoint)-1 // Must have something after the colon
		}
	}
	return false
}
