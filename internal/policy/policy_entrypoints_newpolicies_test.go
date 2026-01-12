package policy

import (
	"context"
	"path/filepath"
	"slices"
	"testing"

	containerv1 "github.com/picatz/deputy/gen/deputy/container/v1"
	dependencyv1 "github.com/picatz/deputy/gen/deputy/dependency/v1"
	policyv1 "github.com/picatz/deputy/gen/deputy/policy/v1"
	vulnerabilityv1 "github.com/picatz/deputy/gen/deputy/vulnerability/v1"
)

func TestCriticalTransitiveSpotlight(t *testing.T) {
	path := filepath.Clean(filepath.Join("..", "..", "policy", "examples", "critical-transitive-spotlight.yaml"))
	sources, err := LoadSources([]string{path})
	if err != nil {
		t.Fatalf("LoadSources: %v", err)
	}

	
	// and severityAtLeast(vulnerability, "CRITICAL")
	payload := map[string]any{
		"vulnerability": &vulnerabilityv1.Finding{
			Advisory: &vulnerabilityv1.Advisory{
				Id: "CVE-2024-1234",
				Severity: &vulnerabilityv1.Severity{
					Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_CRITICAL,
				},
			},
			Package: &dependencyv1.Package{
				Name:   "indirect-dep",
				Direct: false, // transitive dependency
			},
		},
		"env": &policyv1.Environment{Command: "scan", Entrypoint: "scan_vulnerability"},
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
			"request": &policyv1.ProxyRequest{Package: "lodas", Ecosystem: "npm"},
			"env":     &policyv1.Environment{Command: "proxy"},
		}
		if actions, err := EvaluateAll(context.Background(), sources, payload); err != nil || len(actions) == 0 || actions[0].Type != "deny" {
			t.Fatalf("expected deny for typosquat, got %+v err=%v", actions, err)
		}
	})

	t.Run("deny another near miss", func(t *testing.T) {
		payload := map[string]any{
			"request": &policyv1.ProxyRequest{Package: "reqeusts", Ecosystem: "npm"},
			"env":     &policyv1.Environment{Command: "proxy"},
		}
		if actions, err := EvaluateAll(context.Background(), sources, payload); err != nil || len(actions) == 0 || actions[0].Type != "deny" {
			t.Fatalf("expected deny for typosquat, got %+v err=%v", actions, err)
		}
	})

	t.Run("allow safe distant name", func(t *testing.T) {
		payload := map[string]any{
			"request": &policyv1.ProxyRequest{Package: "teamlib", Ecosystem: "npm"},
			"env":     &policyv1.Environment{Command: "proxy"},
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
			"request": &policyv1.ProxyRequest{Package: "@acme/lodas", Ecosystem: "npm"},
			"env":     &policyv1.Environment{Command: "proxy"},
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
			"request": &policyv1.ProxyRequest{Package: "react2", Ecosystem: "npm"},
			"env":     &policyv1.Environment{Command: "proxy"},
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
			"request": &policyv1.ProxyRequest{Package: "lodas", Ecosystem: "npm"},
			"env":     &policyv1.Environment{Command: "scan"},
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
			"vulnerability": &vulnerabilityv1.Finding{
				Advisory: &vulnerabilityv1.Advisory{
					Id: "CVE-2024-1234",
					Severity: &vulnerabilityv1.Severity{
						Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_CRITICAL,
					},
				},
				Package: &dependencyv1.Package{
					Name: "vulnerable-pkg",
					LayerDetails: &containerv1.LayerDetails{
						Index:       1,
						InBaseImage: true,
						Command:     "FROM ubuntu:22.04",
					},
				},
			},
			"env": &policyv1.Environment{Command: "scan", Entrypoint: "scan_vulnerability"},
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
			"vulnerability": &vulnerabilityv1.Finding{
				Advisory: &vulnerabilityv1.Advisory{
					Id: "CVE-2024-5678",
					Severity: &vulnerabilityv1.Severity{
						Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_HIGH,
					},
				},
				Package: &dependencyv1.Package{
					Name:   "app-dep",
					Direct: false, // transitive dependency, not direct
					LayerDetails: &containerv1.LayerDetails{
						Index:       8,
						InBaseImage: false,
						Command:     "COPY --from=builder /app /app",
					},
				},
			},
			"env": &policyv1.Environment{Command: "scan", Entrypoint: "scan_vulnerability"},
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
			"vulnerability": &vulnerabilityv1.Finding{
				Advisory: &vulnerabilityv1.Advisory{
					Id: "CVE-2024-0001",
					Severity: &vulnerabilityv1.Severity{
						Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_HIGH,
					},
				},
				Package: &dependencyv1.Package{
					Name: "base-pkg",
					LayerDetails: &containerv1.LayerDetails{
						Index:       1,
						InBaseImage: true,
					},
				},
			},
			"env": &policyv1.Environment{Command: "scan", Entrypoint: "scan_vulnerability"},
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
			"vulnerability": &vulnerabilityv1.Finding{
				Advisory: &vulnerabilityv1.Advisory{
					Id: "CVE-2024-APT1",
					Severity: &vulnerabilityv1.Severity{
						Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_CRITICAL,
					},
				},
				Package: &dependencyv1.Package{
					Name:   "openssl",
					Direct: false, // transitive dependency
					LayerDetails: &containerv1.LayerDetails{
						Index:       3,
						InBaseImage: false,
						Command:     "RUN apt-get update && apt-get install -y openssl curl",
					},
				},
			},
			"env": &policyv1.Environment{Command: "scan", Entrypoint: "scan_vulnerability"},
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
			"vulnerability": &vulnerabilityv1.Finding{
				Advisory: &vulnerabilityv1.Advisory{
					Id: "CVE-2024-PIP1",
					Severity: &vulnerabilityv1.Severity{
						Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_HIGH,
					},
				},
				Package: &dependencyv1.Package{
					Name:   "requests",
					Direct: false, // transitive dependency
					LayerDetails: &containerv1.LayerDetails{
						Index:       5,
						InBaseImage: false,
						Command:     "RUN pip install requests==2.28.0",
					},
				},
			},
			"env": &policyv1.Environment{Command: "scan", Entrypoint: "scan_vulnerability"},
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
			"vulnerability": &vulnerabilityv1.Finding{
				Advisory: &vulnerabilityv1.Advisory{
					Id: "CVE-2024-NPM1",
					Severity: &vulnerabilityv1.Severity{
						Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_CRITICAL,
					},
				},
				Package: &dependencyv1.Package{
					Name:   "lodash",
					Direct: false, // transitive dependency
					LayerDetails: &containerv1.LayerDetails{
						Index:       6,
						InBaseImage: false,
						Command:     "RUN npm install lodash",
					},
				},
			},
			"env": &policyv1.Environment{Command: "scan", Entrypoint: "scan_vulnerability"},
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
			"vulnerability": &vulnerabilityv1.Finding{
				Advisory: &vulnerabilityv1.Advisory{
					Id: "CVE-2024-NOFIX",
					Severity: &vulnerabilityv1.Severity{
						Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_CRITICAL,
					},
					FixedVersions: []string{}, // no fix available
				},
				Package: &dependencyv1.Package{
					Name: "unfixed-pkg",
					LayerDetails: &containerv1.LayerDetails{
						Index:       2,
						InBaseImage: true,
					},
				},
			},
			"env": &policyv1.Environment{Command: "scan", Entrypoint: "scan_vulnerability"},
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
			"vulnerability": &vulnerabilityv1.Finding{
				Advisory: &vulnerabilityv1.Advisory{
					Id: "CVE-2024-DIRECT",
					Severity: &vulnerabilityv1.Severity{
						Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_HIGH,
					},
				},
				Package: &dependencyv1.Package{
					Name:   "direct-dep",
					Direct: true,
					LayerDetails: &containerv1.LayerDetails{
						Index:       7,
						InBaseImage: false,
					},
				},
			},
			"env": &policyv1.Environment{Command: "scan", Entrypoint: "scan_vulnerability"},
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
			"vulnerability": &vulnerabilityv1.Finding{
				Advisory: &vulnerabilityv1.Advisory{
					Id: "CVE-2024-MED",
					Severity: &vulnerabilityv1.Severity{
						Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_MEDIUM,
					},
				},
				Package: &dependencyv1.Package{
					Name: "medium-pkg",
					LayerDetails: &containerv1.LayerDetails{
						Index:       2,
						InBaseImage: true,
					},
				},
			},
			"env": &policyv1.Environment{Command: "scan", Entrypoint: "scan_vulnerability"},
		}
		actions, err := EvaluateAll(context.Background(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		// Should not trigger deny or warn (only HIGH and CRITICAL trigger)
		for _, a := range actions {
			if a.Type == "deny" || a.Type == "warn" {
				t.Fatalf("did not expect deny/warn for medium severity vulnerability, got %+v", actions)
			}
		}
	})

	t.Run("no action without layerDetails", func(t *testing.T) {
		payload := map[string]any{
			"vulnerability": &vulnerabilityv1.Finding{
				Advisory: &vulnerabilityv1.Advisory{
					Id: "CVE-2024-NOLAYER",
					Severity: &vulnerabilityv1.Severity{
						Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_CRITICAL,
					},
				},
				Package: &dependencyv1.Package{
					Name: "no-layer-pkg",
					// No LayerDetails - not a container scan
				},
			},
			"env": &policyv1.Environment{Command: "scan", Entrypoint: "scan_vulnerability"},
		}
		actions, err := EvaluateAll(context.Background(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		// Should not trigger any action since policies check has(vulnerability.package.layer_details)
		for _, a := range actions {
			if a.Type == "deny" || a.Type == "warn" {
				t.Fatalf("did not expect deny/warn without layer details, got %+v", actions)
			}
		}
	})
}
