package policy

import (
	"context"
	"path/filepath"
	"slices"
	"testing"
)

func TestCriticalTransitiveSpotlight(t *testing.T) {
	path := filepath.Clean(filepath.Join("..", "..", "policy", "examples", "critical-transitive-spotlight.yaml"))
	sources, err := LoadSources([]string{path})
	if err != nil {
		t.Fatalf("LoadSources: %v", err)
	}
	payload := map[string]any{
		"vulnerability": map[string]any{
			"severity": "CRITICAL",
			"isDirect": false,
		},
		"env": map[string]any{"command": "scan", "entrypoint": "scan_vulnerability"},
	}
	actions, err := EvaluateAll(context.Background(), sources, payload)
	if err != nil {
		t.Fatalf("EvaluateAll: %v", err)
	}
	if !slices.ContainsFunc(actions, func(a Action) bool { return a.Type == "warn" }) {
		t.Fatalf("expected warn for critical indirect vuln, got %+v", actions)
	}
}

func TestTyposquatLevenshteinGuard(t *testing.T) {
	path := filepath.Clean(filepath.Join("..", "..", "policy", "examples", "typosquat-levenshtein-guard.yaml"))
	sources, err := LoadSources([]string{path})
	if err != nil {
		t.Fatalf("LoadSources: %v", err)
	}
	t.Run("deny known close typo", func(t *testing.T) {
		payload := map[string]any{
			"request": map[string]any{"package": "lodas", "ecosystem": "npm"},
			"env":     map[string]any{"command": "proxy"},
		}
		if actions, err := EvaluateAll(context.Background(), sources, payload); err != nil || len(actions) == 0 || actions[0].Type != "deny" {
			t.Fatalf("expected deny for typosquat, got %+v err=%v", actions, err)
		}
	})

	t.Run("deny another near miss", func(t *testing.T) {
		payload := map[string]any{
			"request": map[string]any{"package": "reqeusts", "ecosystem": "npm"},
			"env":     map[string]any{"command": "proxy"},
		}
		if actions, err := EvaluateAll(context.Background(), sources, payload); err != nil || len(actions) == 0 || actions[0].Type != "deny" {
			t.Fatalf("expected deny for typosquat, got %+v err=%v", actions, err)
		}
	})

	t.Run("allow safe distant name", func(t *testing.T) {
		payload := map[string]any{
			"request": map[string]any{"package": "teamlib", "ecosystem": "npm"},
			"env":     map[string]any{"command": "proxy"},
		}
		actions, err := EvaluateAll(context.Background(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		for _, a := range actions {
			if a.Type == "deny" {
				t.Fatalf("did not expect deny for distant name: %+v", actions)
			}
		}
	})

	t.Run("allow scoped package", func(t *testing.T) {
		payload := map[string]any{
			"request": map[string]any{"package": "@acme/lodas", "ecosystem": "npm"},
			"env":     map[string]any{"command": "proxy"},
		}
		actions, err := EvaluateAll(context.Background(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		for _, a := range actions {
			if a.Type == "deny" {
				t.Fatalf("did not expect deny for scoped package: %+v", actions)
			}
		}
	})

	t.Run("allow numeric suffix", func(t *testing.T) {
		payload := map[string]any{
			"request": map[string]any{"package": "react2", "ecosystem": "npm"},
			"env":     map[string]any{"command": "proxy"},
		}
		actions, err := EvaluateAll(context.Background(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		for _, a := range actions {
			if a.Type == "deny" {
				t.Fatalf("did not expect deny for numeric suffix: %+v", actions)
			}
		}
	})

	t.Run("ignore non-proxy command", func(t *testing.T) {
		payload := map[string]any{
			"request": map[string]any{"package": "lodas", "ecosystem": "npm"},
			"env":     map[string]any{"command": "scan"},
		}
		actions, err := EvaluateAll(context.Background(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		for _, a := range actions {
			if a.Type == "deny" {
				t.Fatalf("did not expect deny outside proxy: %+v", actions)
			}
		}
	})
}

func TestContainerLayerVulnerabilityPolicies(t *testing.T) {
	path := filepath.Clean(filepath.Join("..", "..", "policy", "examples", "container-layer-vulnerability.yaml"))
	sources, err := LoadSources([]string{path})
	if err != nil {
		t.Fatalf("LoadSources: %v", err)
	}

	t.Run("deny critical base image vulnerability", func(t *testing.T) {
		payload := map[string]any{
			"vulnerability": map[string]any{
				"id":       "CVE-2024-1234",
				"severity": "CRITICAL",
				"layerDetails": map[string]any{
					"index":       1,
					"inBaseImage": true,
					"command":     "FROM ubuntu:22.04",
				},
			},
			"env": map[string]any{"command": "scan", "entrypoint": "scan_vulnerability"},
		}
		actions, err := EvaluateAll(context.Background(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		if !slices.ContainsFunc(actions, func(a Action) bool { return a.Type == "deny" }) {
			t.Fatalf("expected deny for critical base image vulnerability, got %+v", actions)
		}
	})

	t.Run("warn on high severity application layer vulnerability", func(t *testing.T) {
		payload := map[string]any{
			"vulnerability": map[string]any{
				"id":       "CVE-2024-5678",
				"severity": "HIGH",
				"isDirect": false, // transitive dependency, not direct
				"layerDetails": map[string]any{
					"index":       8,
					"inBaseImage": false,
					"command":     "COPY --from=builder /app /app",
				},
			},
			"env": map[string]any{"command": "scan", "entrypoint": "scan_vulnerability"},
		}
		actions, err := EvaluateAll(context.Background(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		if !slices.ContainsFunc(actions, func(a Action) bool { return a.Type == "warn" }) {
			t.Fatalf("expected warn for high severity application layer vulnerability, got %+v", actions)
		}
	})

	t.Run("warn on early base layer vulnerability", func(t *testing.T) {
		payload := map[string]any{
			"vulnerability": map[string]any{
				"id":       "CVE-2024-0001",
				"severity": "HIGH",
				"layerDetails": map[string]any{
					"index":       1,
					"inBaseImage": true,
				},
			},
			"env": map[string]any{"command": "scan", "entrypoint": "scan_vulnerability"},
		}
		actions, err := EvaluateAll(context.Background(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		if !slices.ContainsFunc(actions, func(a Action) bool { return a.Type == "warn" }) {
			t.Fatalf("expected warn for early base layer vulnerability, got %+v", actions)
		}
	})

	t.Run("warn on apt-get installed vulnerability", func(t *testing.T) {
		payload := map[string]any{
			"vulnerability": map[string]any{
				"id":       "CVE-2024-APT1",
				"severity": "CRITICAL",
				"package":  "openssl",
				"isDirect": false, // transitive dependency
				"layerDetails": map[string]any{
					"index":       3,
					"inBaseImage": false,
					"command":     "RUN apt-get update && apt-get install -y openssl curl",
				},
			},
			"env": map[string]any{"command": "scan", "entrypoint": "scan_vulnerability"},
		}
		actions, err := EvaluateAll(context.Background(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		if !slices.ContainsFunc(actions, func(a Action) bool { return a.Type == "warn" }) {
			t.Fatalf("expected warn for apt-get installed vulnerability, got %+v", actions)
		}
	})

	t.Run("warn on pip installed vulnerability", func(t *testing.T) {
		payload := map[string]any{
			"vulnerability": map[string]any{
				"id":       "CVE-2024-PIP1",
				"severity": "HIGH",
				"package":  "requests",
				"isDirect": false, // transitive dependency
				"layerDetails": map[string]any{
					"index":       5,
					"inBaseImage": false,
					"command":     "RUN pip install requests==2.28.0",
				},
			},
			"env": map[string]any{"command": "scan", "entrypoint": "scan_vulnerability"},
		}
		actions, err := EvaluateAll(context.Background(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		if !slices.ContainsFunc(actions, func(a Action) bool { return a.Type == "warn" }) {
			t.Fatalf("expected warn for pip installed vulnerability, got %+v", actions)
		}
	})

	t.Run("warn on npm installed vulnerability", func(t *testing.T) {
		payload := map[string]any{
			"vulnerability": map[string]any{
				"id":       "CVE-2024-NPM1",
				"severity": "CRITICAL",
				"package":  "lodash",
				"isDirect": false, // transitive dependency
				"layerDetails": map[string]any{
					"index":       6,
					"inBaseImage": false,
					"command":     "RUN npm install lodash",
				},
			},
			"env": map[string]any{"command": "scan", "entrypoint": "scan_vulnerability"},
		}
		actions, err := EvaluateAll(context.Background(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		if !slices.ContainsFunc(actions, func(a Action) bool { return a.Type == "warn" }) {
			t.Fatalf("expected warn for npm installed vulnerability, got %+v", actions)
		}
	})

	t.Run("deny unfixed critical base image vulnerability", func(t *testing.T) {
		payload := map[string]any{
			"vulnerability": map[string]any{
				"id":            "CVE-2024-NOFIX",
				"severity":      "CRITICAL",
				"fixedVersions": []any{},
				"layerDetails": map[string]any{
					"index":       2,
					"inBaseImage": true,
				},
			},
			"env": map[string]any{"command": "scan", "entrypoint": "scan_vulnerability"},
		}
		actions, err := EvaluateAll(context.Background(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		if !slices.ContainsFunc(actions, func(a Action) bool { return a.Type == "deny" }) {
			t.Fatalf("expected deny for unfixed critical base image vulnerability, got %+v", actions)
		}
	})

	t.Run("deny high severity direct dependency in application layer", func(t *testing.T) {
		payload := map[string]any{
			"vulnerability": map[string]any{
				"id":       "CVE-2024-DIRECT",
				"severity": "HIGH",
				"isDirect": true,
				"layerDetails": map[string]any{
					"index":       7,
					"inBaseImage": false,
				},
			},
			"env": map[string]any{"command": "scan", "entrypoint": "scan_vulnerability"},
		}
		actions, err := EvaluateAll(context.Background(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		if !slices.ContainsFunc(actions, func(a Action) bool { return a.Type == "deny" }) {
			t.Fatalf("expected deny for direct dependency vulnerability in application layer, got %+v", actions)
		}
	})

	t.Run("no action on medium severity base image vulnerability", func(t *testing.T) {
		payload := map[string]any{
			"vulnerability": map[string]any{
				"id":       "CVE-2024-MED",
				"severity": "MEDIUM",
				"layerDetails": map[string]any{
					"index":       2,
					"inBaseImage": true,
				},
			},
			"env": map[string]any{"command": "scan", "entrypoint": "scan_vulnerability"},
		}
		actions, err := EvaluateAll(context.Background(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		// Should not trigger deny or warn for medium severity
		for _, a := range actions {
			if a.Type == "deny" {
				t.Fatalf("did not expect deny for medium severity: %+v", actions)
			}
		}
	})

	t.Run("no action without layerDetails", func(t *testing.T) {
		payload := map[string]any{
			"vulnerability": map[string]any{
				"id":       "GO-2024-1234",
				"severity": "CRITICAL",
			},
			"env": map[string]any{"command": "scan", "entrypoint": "scan_vulnerability"},
		}
		actions, err := EvaluateAll(context.Background(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		// These policies require layerDetails, so no actions expected for regular vulnerabilities
		for _, a := range actions {
			if a.Type == "deny" {
				t.Fatalf("did not expect deny without layerDetails: %+v", actions)
			}
		}
	})
}

// TestScanVulnerabilityWithImageConfig verifies that image.config is available
// in scan_vulnerability entrypoint, allowing cross-reference policies that
// combine vulnerability data with image configuration.
func TestScanVulnerabilityWithImageConfig(t *testing.T) {
	// Policy that denies critical vulnerabilities in images running as root
	policyYAML := `
policies:
  - name: root-with-critical-vuln
    description: Block critical vulnerabilities in images running as root
    entrypoints: ["scan_vulnerability"]
    rules:
      - action: deny
        when: |
          has(image.config) &&
          image.config.is_root == true &&
          vulnerability.severity == "CRITICAL"
        reason: "Critical vulnerability in image running as root"
        remediation: "Use non-root user or fix the vulnerability"
`
	sources, err := ParseStructuredSources([]byte(policyYAML), "test-policy.yaml")
	if err != nil {
		t.Fatalf("ParseStructuredSources: %v", err)
	}

	t.Run("deny critical vuln in root image", func(t *testing.T) {
		payload := map[string]any{
			"vulnerability": map[string]any{
				"id":       "CVE-2024-ROOT",
				"severity": "CRITICAL",
			},
			"image_info": map[string]any{
				"config": map[string]any{
					"user":    "",
					"is_root": true,
				},
			},
			"env": map[string]any{"command": "scan", "entrypoint": "scan_vulnerability"},
		}
		actions, err := EvaluateAll(context.Background(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		if !slices.ContainsFunc(actions, func(a Action) bool { return a.Type == "deny" }) {
			t.Fatalf("expected deny for critical vuln in root image, got %+v", actions)
		}
	})

	t.Run("allow critical vuln in non-root image", func(t *testing.T) {
		payload := map[string]any{
			"vulnerability": map[string]any{
				"id":       "CVE-2024-NONROOT",
				"severity": "CRITICAL",
			},
			"image_info": map[string]any{
				"config": map[string]any{
					"user":    "nobody",
					"is_root": false,
				},
			},
			"env": map[string]any{"command": "scan", "entrypoint": "scan_vulnerability"},
		}
		actions, err := EvaluateAll(context.Background(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		for _, a := range actions {
			if a.Type == "deny" {
				t.Fatalf("did not expect deny for non-root image: %+v", actions)
			}
		}
	})

	t.Run("allow medium vuln in root image", func(t *testing.T) {
		payload := map[string]any{
			"vulnerability": map[string]any{
				"id":       "CVE-2024-MED",
				"severity": "MEDIUM",
			},
			"image_info": map[string]any{
				"config": map[string]any{
					"user":    "",
					"is_root": true,
				},
			},
			"env": map[string]any{"command": "scan", "entrypoint": "scan_vulnerability"},
		}
		actions, err := EvaluateAll(context.Background(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		for _, a := range actions {
			if a.Type == "deny" {
				t.Fatalf("did not expect deny for medium vuln: %+v", actions)
			}
		}
	})

	t.Run("no image config - policy does not match", func(t *testing.T) {
		payload := map[string]any{
			"vulnerability": map[string]any{
				"id":       "CVE-2024-NOIMG",
				"severity": "CRITICAL",
			},
			"env": map[string]any{"command": "scan", "entrypoint": "scan_vulnerability"},
		}
		actions, err := EvaluateAll(context.Background(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		for _, a := range actions {
			if a.Type == "deny" {
				t.Fatalf("did not expect deny without image config: %+v", actions)
			}
		}
	})
}
