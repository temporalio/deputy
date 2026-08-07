package policy

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	policyv1 "github.com/temporalio/deputy/gen/deputy/policy/v1"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
)

// findExample returns the path to a named example policy in policy/examples.
func findExample(t *testing.T, name string) string {
	t.Helper()
	rel := filepath.Join("..", "..", "policy", "examples", name)
	return filepath.Clean(rel)
}

func loadAllowlist(t *testing.T) []Source {
	t.Helper()
	path := findExample(t, "license-allowlist.yaml")
	sources, err := LoadSources([]string{path})
	if err != nil {
		t.Fatalf("LoadSources(%s): %v", path, err)
	}
	return sources
}

func TestLicenseAllowlistEntrypoints(t *testing.T) {
	sources := loadAllowlist(t)

	t.Run("sbom component denies copyleft", func(t *testing.T) {
		payload := map[string]any{
			"pkg": &dependencyv1.Package{
				Name:     "test-pkg",
				Version:  "1.0.0",
				Licenses: []string{"GPL-3.0"},
			},
			"env": &policyv1.Environment{Command: "sbom"},
		}
		actions, err := EvaluateMap(t.Context(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		if len(actions) != 1 || actions[0].Type != "deny" {
			t.Fatalf("expected one deny action, got %+v", actions)
		}
	})

	t.Run("proxy request denies copyleft", func(t *testing.T) {
		// For proxy requests, pkg contains the package info with licenses.
		payload := map[string]any{
			"pkg": &dependencyv1.Package{
				Name:     "test-pkg",
				Version:  "1.0.0",
				Licenses: []string{"AGPL-3.0-only"},
			},
			"env": &policyv1.Environment{Command: "proxy"},
		}
		actions, err := EvaluateMap(t.Context(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		if len(actions) != 1 || actions[0].Type != "deny" {
			t.Fatalf("expected one deny action, got %+v", actions)
		}
	})

	t.Run("sbom warn on missing licenses", func(t *testing.T) {
		payload := map[string]any{
			"pkg": &dependencyv1.Package{Name: "test-pkg"},
			"env": &policyv1.Environment{Command: "sbom"},
		}
		actions, err := EvaluateMap(t.Context(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		if len(actions) != 1 || actions[0].Type != "warn" {
			t.Fatalf("expected one warn action, got %+v", actions)
		}
	})

	t.Run("scan payload does not error", func(t *testing.T) {
		payload := map[string]any{
			"pkg": &dependencyv1.Package{Name: "test-pkg"},
			"env": &policyv1.Environment{Command: "scan"},
		}
		actions, err := EvaluateMap(t.Context(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		// The policy may emit a warn for missing licenses; just ensure no deny.
		for _, act := range actions {
			if act.Type == "deny" {
				t.Fatalf("did not expect deny for scan payload: %+v", act)
			}
		}
	})
}

func loadAllowlistComposed(t *testing.T) []Source {
	t.Helper()
	path := findExample(t, "license-allowlist-composed.yaml")
	sources, err := LoadSources([]string{path})
	if err != nil {
		t.Fatalf("LoadSources(%s): %v", path, err)
	}
	return sources
}

func TestLicenseAllowlistComposedEntrypoints(t *testing.T) {
	sources := loadAllowlistComposed(t)

	t.Run("vars compose normalized and license_list", func(t *testing.T) {
		payload := map[string]any{
			"pkg": &dependencyv1.Package{
				Name:     "test-pkg",
				Version:  "1.0.0",
				Licenses: []string{"AgPl-3.0-only", "mit"},
			},
			"env": &policyv1.Environment{Command: "sbom"},
		}
		actions, err := EvaluateMap(t.Context(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		if len(actions) != 1 || actions[0].Type != "deny" {
			t.Fatalf("expected one deny action, got %+v", actions)
		}
		if !strings.Contains(strings.ToLower(actions[0].Reason), "forbidden") {
			t.Fatalf("expected reason to include forbidden licenses, got %q", actions[0].Reason)
		}
	})

	t.Run("sbom component denies copyleft", func(t *testing.T) {
		payload := map[string]any{
			"pkg": &dependencyv1.Package{
				Name:     "test-pkg",
				Version:  "1.0.0",
				Licenses: []string{"GPL-3.0"},
			},
			"env": &policyv1.Environment{Command: "sbom"},
		}
		actions, err := EvaluateMap(t.Context(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		if len(actions) != 1 || actions[0].Type != "deny" {
			t.Fatalf("expected one deny action, got %+v", actions)
		}
	})

	t.Run("proxy request denies copyleft", func(t *testing.T) {
		payload := map[string]any{
			"pkg": &dependencyv1.Package{
				Name:     "test-pkg",
				Version:  "1.0.0",
				Licenses: []string{"AGPL-3.0-ONLY"},
			},
			"env": &policyv1.Environment{Command: "proxy"},
		}
		actions, err := EvaluateMap(t.Context(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		if len(actions) != 1 || actions[0].Type != "deny" {
			t.Fatalf("expected one deny action, got %+v", actions)
		}
	})

	t.Run("sbom warn on missing licenses", func(t *testing.T) {
		payload := map[string]any{
			"pkg": &dependencyv1.Package{Name: "test-pkg"},
			"env": &policyv1.Environment{Command: "sbom"},
		}
		actions, err := EvaluateMap(t.Context(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		if len(actions) != 1 || actions[0].Type != "warn" {
			t.Fatalf("expected one warn action, got %+v", actions)
		}
	})
}

func TestLicenseAllowlistHappySadPaths(t *testing.T) {
	sources := loadAllowlist(t)

	t.Run("happy path allows permissive license", func(t *testing.T) {
		payload := map[string]any{
			"pkg": &dependencyv1.Package{
				Name:     "test-pkg",
				Licenses: []string{"MIT"},
			},
			"env": &policyv1.Environment{Command: "sbom"},
		}
		actions, err := EvaluateMap(t.Context(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		for _, a := range actions {
			if strings.EqualFold(a.Type, "deny") {
				t.Fatalf("did not expect deny: %+v", a)
			}
		}
	})

	t.Run("sad path denies copyleft", func(t *testing.T) {
		payload := map[string]any{
			"pkg": &dependencyv1.Package{
				Name:     "test-pkg",
				Licenses: []string{"GPL-3.0-only"},
			},
			"env": &policyv1.Environment{Command: "proxy"},
		}
		actions, err := EvaluateMap(t.Context(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		if !slices.ContainsFunc(actions, func(a Action) bool { return a.Type == "deny" }) {
			t.Fatalf("expected deny, got %+v", actions)
		}
	})
}

func TestDenyAwsSdkV1Policy(t *testing.T) {
	path := filepath.Clean(filepath.Join("..", "..", "policy", "examples", "deny-aws-sdk-v1.yaml"))
	sources, err := LoadSources([]string{path})
	if err != nil {
		t.Fatalf("LoadSources: %v", err)
	}

	t.Run("deny v1", func(t *testing.T) {
		payload := map[string]any{
			"pkg": &dependencyv1.Package{
				Ecosystem: "go",
				Name:      "github.com/aws/aws-sdk-go",
				Version:   "v1.44.0",
			},
			"env": &policyv1.Environment{Command: "proxy"},
		}
		actions, err := EvaluateMap(t.Context(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		deny := false
		for _, a := range actions {
			if a.Type == "deny" {
				deny = true
			}
		}
		if !deny {
			t.Fatalf("expected deny for v1, got %+v", actions)
		}
	})

	t.Run("allow v2", func(t *testing.T) {
		payload := map[string]any{
			"pkg": &dependencyv1.Package{
				Ecosystem: "go",
				Name:      "github.com/aws/aws-sdk-go-v2",
				Version:   "v1.0.0",
			},
			"env": &policyv1.Environment{Command: "proxy"},
		}
		actions, err := EvaluateMap(t.Context(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		for _, a := range actions {
			if a.Type == "deny" {
				t.Fatalf("did not expect deny for v2: %+v", actions)
			}
		}
	})
}

func TestGoModRegistryAllowlist(t *testing.T) {
	path := filepath.Clean(filepath.Join("..", "..", "policy", "examples", "gomod-registry-allowlist.yaml"))
	sources, err := LoadSources([]string{path})
	if err != nil {
		t.Fatalf("LoadSources: %v", err)
	}

	t.Run("deny unapproved org", func(t *testing.T) {
		payload := map[string]any{
			"pkg": &dependencyv1.Package{
				Ecosystem: "go",
				Name:      "github.com/badorg/module",
				Version:   "v1.0.0",
			},
			"env": &policyv1.Environment{Command: "proxy"},
		}
		actions, err := EvaluateMap(t.Context(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		deny := false
		for _, a := range actions {
			if a.Type == "deny" {
				deny = true
			}
		}
		if !deny {
			t.Fatalf("expected deny for unapproved org, got %+v", actions)
		}
	})

	t.Run("allow approved org", func(t *testing.T) {
		payload := map[string]any{
			"pkg": &dependencyv1.Package{
				Ecosystem: "go",
				Name:      "github.com/org-a/module",
				Version:   "v1.2.3",
			},
			"env": &policyv1.Environment{Command: "proxy"},
		}
		actions, err := EvaluateMap(t.Context(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		for _, a := range actions {
			if a.Type == "deny" {
				t.Fatalf("did not expect deny for approved org: %+v", actions)
			}
		}
	})
}

func TestGoPseudoVersionDenyPolicy(t *testing.T) {
	path := filepath.Clean(filepath.Join("..", "..", "policy", "examples", "go-pseudo-version-deny.yaml"))
	sources, err := LoadSources([]string{path})
	if err != nil {
		t.Fatalf("LoadSources: %v", err)
	}

	t.Run("deny pseudo with 0 qualifier", func(t *testing.T) {
		payload := map[string]any{
			"pkg": &dependencyv1.Package{
				Ecosystem: "go",
				Name:      "github.com/example/module",
				Version:   "v1.2.3-0.20240528123456-deadbeefcafe",
			},
		}
		actions, err := EvaluateMap(t.Context(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		deny := false
		for _, a := range actions {
			if a.Type == "deny" {
				deny = true
			}
		}
		if !deny {
			t.Fatalf("expected deny for pseudo-version, got %+v", actions)
		}
	})

	t.Run("deny bare pseudo version", func(t *testing.T) {
		payload := map[string]any{
			"pkg": &dependencyv1.Package{
				Ecosystem: "go",
				Name:      "github.com/example/module",
				Version:   "v0.0.0-20170915030341-ba0f2cc1c8ab",
			},
		}
		actions, err := EvaluateMap(t.Context(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		deny := false
		for _, a := range actions {
			if a.Type == "deny" {
				deny = true
			}
		}
		if !deny {
			t.Fatalf("expected deny for bare pseudo-version, got %+v", actions)
		}
	})

	t.Run("allow tagged release", func(t *testing.T) {
		payload := map[string]any{
			"pkg": &dependencyv1.Package{
				Ecosystem: "go",
				Name:      "github.com/example/module",
				Version:   "v1.2.3",
			},
		}
		actions, err := EvaluateMap(t.Context(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		for _, a := range actions {
			if a.Type == "deny" {
				t.Fatalf("did not expect deny for tagged release: %+v", actions)
			}
		}
	})
}

func TestPrereleaseGuardPolicy(t *testing.T) {
	path := filepath.Clean(filepath.Join("..", "..", "policy", "examples", "prerelease-guard.yaml"))
	sources, err := LoadSources([]string{path})
	if err != nil {
		t.Fatalf("LoadSources: %v", err)
	}

	t.Run("deny prerelease by default", func(t *testing.T) {
		payload := map[string]any{
			"pkg": &dependencyv1.Package{
				Version: "v1.2.3-beta.1",
			},
		}
		actions, err := EvaluateMap(t.Context(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		if !slices.ContainsFunc(actions, func(a Action) bool { return a.Type == "deny" }) {
			t.Fatalf("expected deny for prerelease version, got %+v", actions)
		}
	})

	t.Run("allow stable release", func(t *testing.T) {
		payload := map[string]any{
			"pkg": &dependencyv1.Package{
				Version: "1.2.3",
			},
		}
		actions, err := EvaluateMap(t.Context(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		for _, a := range actions {
			if a.Type == "deny" {
				t.Fatalf("did not expect deny for stable release: %+v", actions)
			}
		}
	})
}

func TestDirectHighFixBlock(t *testing.T) {
	path := filepath.Clean(filepath.Join("..", "..", "policy", "examples", "direct-high-fix-block.yaml"))
	sources, err := LoadSources([]string{path})
	if err != nil {
		t.Fatalf("LoadSources: %v", err)
	}

	// vulnerability.advisory.fixed_versions, so we must use proto types.
	t.Run("deny direct high with fix", func(t *testing.T) {
		payload := map[string]any{
			"vulnerability": &vulnerabilityv1.Finding{
				Advisory: &vulnerabilityv1.Advisory{
					Id: "CVE-2024-1234",
					Severity: &vulnerabilityv1.Severity{
						Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_HIGH,
					},
					FixedVersions: []string{"v1.2.3"},
				},
				Package: &dependencyv1.Package{
					Name:   "example-pkg",
					Direct: true,
				},
			},
			"env": &policyv1.Environment{Command: "scan", Entrypoint: "scan_vulnerability"},
		}
		actions, err := EvaluateMap(t.Context(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		deny := false
		for _, a := range actions {
			if a.Type == "deny" {
				deny = true
			}
		}
		if !deny {
			t.Fatalf("expected deny, got %+v", actions)
		}
	})

	t.Run("allow medium", func(t *testing.T) {
		payload := map[string]any{
			"vulnerability": &vulnerabilityv1.Finding{
				Advisory: &vulnerabilityv1.Advisory{
					Id: "CVE-2024-5678",
					Severity: &vulnerabilityv1.Severity{
						Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_MEDIUM,
					},
					FixedVersions: []string{"v1.2.3"},
				},
				Package: &dependencyv1.Package{
					Name:   "example-pkg",
					Direct: true,
				},
			},
			"env": &policyv1.Environment{Command: "scan", Entrypoint: "scan_vulnerability"},
		}
		actions, err := EvaluateMap(t.Context(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		for _, a := range actions {
			if a.Type == "deny" {
				t.Fatalf("did not expect deny for medium: %+v", actions)
			}
		}
	})
}

func TestNewDependencyReview(t *testing.T) {
	path := filepath.Clean(filepath.Join("..", "..", "policy", "examples", "new-dependency-review.yaml"))
	sources, err := LoadSources([]string{path})
	if err != nil {
		t.Fatalf("LoadSources: %v", err)
	}

	t.Run("deny unapproved addition", func(t *testing.T) {
		pkg := &dependencyv1.Package{Name: "github.com/unapproved/module", Ecosystem: "go"}
		payload := map[string]any{
			"change": map[string]any{
				"type": "added",
			},
			"pkg": pkg,
			"env": &policyv1.Environment{Command: "diff", Entrypoint: "diff_dependency_change"},
		}
		actions, err := EvaluateMap(t.Context(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		deny := false
		for _, a := range actions {
			if a.Type == "deny" {
				deny = true
			}
		}
		if !deny {
			t.Fatalf("expected deny for unapproved addition, got %+v", actions)
		}
	})

	t.Run("allow approved addition", func(t *testing.T) {
		pkg := &dependencyv1.Package{Name: "github.com/acme/lib", Ecosystem: "go"}
		payload := map[string]any{
			"change": map[string]any{
				"type": "added",
			},
			"pkg": pkg,
			"env": &policyv1.Environment{Command: "diff", Entrypoint: "diff_dependency_change"},
		}
		actions, err := EvaluateMap(t.Context(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		for _, a := range actions {
			if a.Type == "deny" {
				t.Fatalf("did not expect deny for approved addition: %+v", actions)
			}
		}
	})
}

func TestFixStepCommandAllowlist(t *testing.T) {
	path := filepath.Clean(filepath.Join("..", "..", "policy", "examples", "fix-step-command-allowlist.yaml"))
	sources, err := LoadSources([]string{path})
	if err != nil {
		t.Fatalf("LoadSources: %v", err)
	}

	t.Run("deny unsafe command", func(t *testing.T) {
		payload := map[string]any{
			"step": map[string]any{
				"command":    "rm -rf /",
				"executable": true,
			},
			"env": &policyv1.Environment{Command: "fix", Entrypoint: "fix_plan_step"},
		}
		actions, err := EvaluateMap(t.Context(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		deny := false
		for _, a := range actions {
			if a.Type == "deny" {
				deny = true
			}
		}
		if !deny {
			t.Fatalf("expected deny for unsafe command, got %+v", actions)
		}
	})

	t.Run("allow vetted command", func(t *testing.T) {
		payload := map[string]any{
			"step": map[string]any{
				"command":    "go get github.com/example/mod@v1.2.3",
				"executable": true,
			},
			"env": &policyv1.Environment{Command: "fix", Entrypoint: "fix_plan_step"},
		}
		actions, err := EvaluateMap(t.Context(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		for _, a := range actions {
			if a.Type == "deny" {
				t.Fatalf("did not expect deny for allowed command: %+v", actions)
			}
		}
	})
}

func TestSbomMetadataQuality(t *testing.T) {
	path := filepath.Clean(filepath.Join("..", "..", "policy", "examples", "sbom-metadata-quality.yaml"))
	sources, err := LoadSources([]string{path})
	if err != nil {
		t.Fatalf("LoadSources: %v", err)
	}

	t.Run("warn when version missing", func(t *testing.T) {
		payload := map[string]any{
			"pkg": &dependencyv1.Package{
				Name: "example",
				// Version missing - should trigger warn
			},
			"env": &policyv1.Environment{Command: "sbom", Entrypoint: "sbom_component"},
		}
		actions, err := EvaluateMap(t.Context(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		warn := false
		for _, a := range actions {
			if a.Type == "warn" {
				warn = true
			}
		}
		if !warn {
			t.Fatalf("expected warn for missing metadata, got %+v", actions)
		}
	})

	t.Run("no warn when metadata present", func(t *testing.T) {
		payload := map[string]any{
			"pkg": &dependencyv1.Package{
				Name:      "example",
				Version:   "1.0.0",
				Ecosystem: "pypi", // This is what the proto uses instead of purlType
			},
			"env": &policyv1.Environment{Command: "sbom", Entrypoint: "sbom_component"},
		}
		actions, err := EvaluateMap(t.Context(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		for _, a := range actions {
			if a.Type == "warn" || a.Type == "deny" {
				t.Fatalf("did not expect warn/deny for complete metadata: %+v", actions)
			}
		}
	})
}

func TestUnstableMajorGuard(t *testing.T) {
	path := filepath.Clean(filepath.Join("..", "..", "policy", "examples", "unstable-major-guard.yaml"))
	sources, err := LoadSources([]string{path})
	if err != nil {
		t.Fatalf("LoadSources: %v", err)
	}

	t.Run("warn on v0 version", func(t *testing.T) {
		payload := map[string]any{
			"pkg": &dependencyv1.Package{
				Ecosystem: "go",
				Version:   "v0.9.1",
			},
			"env": &policyv1.Environment{Command: "proxy"},
		}
		actions, err := EvaluateMap(t.Context(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		warn := false
		for _, a := range actions {
			if a.Type == "warn" {
				warn = true
			}
		}
		if !warn {
			t.Fatalf("expected warn for v0, got %+v", actions)
		}
	})

	t.Run("allow stable version", func(t *testing.T) {
		payload := map[string]any{
			"pkg": &dependencyv1.Package{
				Ecosystem: "go",
				Version:   "1.2.3",
			},
			"env": &policyv1.Environment{Command: "proxy"},
		}
		actions, err := EvaluateMap(t.Context(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		for _, a := range actions {
			if a.Type == "warn" || a.Type == "deny" {
				t.Fatalf("did not expect warn/deny for stable version: %+v", actions)
			}
		}
	})
}

func TestPypiPrefixAllowlist(t *testing.T) {
	path := filepath.Clean(filepath.Join("..", "..", "policy", "examples", "pypi-prefix-allowlist.yaml"))
	sources, err := LoadSources([]string{path})
	if err != nil {
		t.Fatalf("LoadSources: %v", err)
	}

	t.Run("deny unapproved prefix", func(t *testing.T) {
		payload := map[string]any{
			"pkg": &dependencyv1.Package{
				Name:      "randompkg",
				Ecosystem: "pypi",
			},
			"request": &policyv1.ProxyRequest{
				Ecosystem: "pypi",
				Package:   "randompkg",
			},
			"env": &policyv1.Environment{Command: "proxy", Entrypoint: "pypi_artifact_request"},
		}
		actions, err := EvaluateMap(t.Context(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		deny := false
		for _, a := range actions {
			if a.Type == "deny" {
				deny = true
			}
		}
		if !deny {
			t.Fatalf("expected deny for unapproved PyPI package, got %+v", actions)
		}
	})

	t.Run("allow approved prefix", func(t *testing.T) {
		payload := map[string]any{
			"pkg": &dependencyv1.Package{
				Name:      "acme_toolkit",
				Ecosystem: "pypi",
			},
			"request": &policyv1.ProxyRequest{
				Ecosystem: "pypi",
				Package:   "acme_toolkit",
			},
			"env": &policyv1.Environment{Command: "proxy", Entrypoint: "pypi_artifact_request"},
		}
		actions, err := EvaluateMap(t.Context(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		for _, a := range actions {
			if a.Type == "deny" {
				t.Fatalf("did not expect deny for approved PyPI package: %+v", actions)
			}
		}
	})
}

func TestDependencyCountGuard(t *testing.T) {
	path := filepath.Clean(filepath.Join("..", "..", "policy", "examples", "dependency-count-guard.yaml"))
	sources, err := LoadSources([]string{path})
	if err != nil {
		t.Fatalf("LoadSources: %v", err)
	}

	denyPayload := map[string]any{
		"changes": make([]any, 80),
		"env":     &policyv1.Environment{Command: "diff", Entrypoint: "diff_report"},
	}
	if actions, err := EvaluateMap(t.Context(), sources, denyPayload); err != nil || len(actions) == 0 || actions[0].Type != "deny" {
		t.Fatalf("expected deny for large change set, got %+v err=%v", actions, err)
	}

	warnPayload := map[string]any{
		"changes": make([]any, 30),
		"env":     &policyv1.Environment{Command: "diff", Entrypoint: "diff_report"},
	}
	actions, err := EvaluateMap(t.Context(), sources, warnPayload)
	if err != nil {
		t.Fatalf("EvaluateAll: %v", err)
	}
	if !slices.ContainsFunc(actions, func(a Action) bool { return a.Type == "warn" }) {
		t.Fatalf("expected warn for medium change set, got %+v", actions)
	}
}

func TestLicensePresentBlocker(t *testing.T) {
	path := filepath.Clean(filepath.Join("..", "..", "policy", "examples", "license-present-blocker.yaml"))
	sources, err := LoadSources([]string{path})
	if err != nil {
		t.Fatalf("LoadSources: %v", err)
	}
	denyPayload := map[string]any{
		"pkg": &dependencyv1.Package{Licenses: []string{}},
		"env": &policyv1.Environment{Command: "proxy"},
	}
	if actions, err := EvaluateMap(t.Context(), sources, denyPayload); err != nil || len(actions) == 0 || actions[0].Type != "deny" {
		t.Fatalf("expected deny for missing licenses, got %+v err=%v", actions, err)
	}
	allowPayload := map[string]any{
		"pkg": &dependencyv1.Package{Licenses: []string{"MIT"}},
		"env": &policyv1.Environment{Command: "proxy"},
	}
	if actions, err := EvaluateMap(t.Context(), sources, allowPayload); err != nil {
		t.Fatalf("EvaluateAll: %v", err)
	} else {
		for _, a := range actions {
			if a.Type == "deny" {
				t.Fatalf("did not expect deny: %+v", actions)
			}
		}
	}
}

func TestNoFixEscalator(t *testing.T) {
	path := filepath.Clean(filepath.Join("..", "..", "policy", "examples", "no-fix-escalator.yaml"))
	sources, err := LoadSources([]string{path})
	if err != nil {
		t.Fatalf("LoadSources: %v", err)
	}

	// vulnerability.advisory.severity.level
	payload := map[string]any{
		"vulnerability": &vulnerabilityv1.Finding{
			Package: &dependencyv1.Package{
				Direct: true,
			},
			Advisory: &vulnerabilityv1.Advisory{
				FixedVersions: []string{},
				Severity: &vulnerabilityv1.Severity{
					Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_HIGH,
				},
			},
		},
		"env": &policyv1.Environment{Command: "scan", Entrypoint: "scan_vulnerability"},
	}
	actions, err := EvaluateMap(t.Context(), sources, payload)
	if err != nil {
		t.Fatalf("EvaluateAll: %v", err)
	}
	warn := false
	for _, a := range actions {
		if a.Type == "warn" {
			warn = true
		}
	}
	if !warn {
		t.Fatalf("expected warn for no-fix direct vuln, got %+v", actions)
	}
}

func TestProdManifestGate(t *testing.T) {
	path := filepath.Clean(filepath.Join("..", "..", "policy", "examples", "prod-manifest-gate.yaml"))
	sources, err := LoadSources([]string{path})
	if err != nil {
		t.Fatalf("LoadSources: %v", err)
	}

	payload := map[string]any{
		"vulnerability": &vulnerabilityv1.Finding{
			Package: &dependencyv1.Package{
				ManifestRefs: []*dependencyv1.ManifestRef{
					{Groups: []string{"prod"}},
				},
			},
			Advisory: &vulnerabilityv1.Advisory{
				Severity: &vulnerabilityv1.Severity{
					Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_CRITICAL,
				},
			},
		},
		"env": &policyv1.Environment{Command: "scan", Entrypoint: "scan_vulnerability"},
	}
	if actions, err := EvaluateMap(t.Context(), sources, payload); err != nil || len(actions) == 0 || actions[0].Type != "deny" {
		t.Fatalf("expected deny for prod manifest vuln, got %+v err=%v", actions, err)
	}
}

func TestDomainBrandedPackageGuard(t *testing.T) {
	path := filepath.Clean(filepath.Join("..", "..", "policy", "examples", "domain-branded-package-guard.yaml"))
	sources, err := LoadSources([]string{path})
	if err != nil {
		t.Fatalf("LoadSources: %v", err)
	}
	payload := map[string]any{
		"pkg": &dependencyv1.Package{
			Name: "aws-helper",
		},
		"request": &policyv1.ProxyRequest{
			Package: "aws-helper",
		},
		"env": &policyv1.Environment{Command: "proxy"},
	}
	if actions, err := EvaluateMap(t.Context(), sources, payload); err != nil || len(actions) == 0 || actions[0].Type != "deny" {
		t.Fatalf("expected deny for branded package, got %+v err=%v", actions, err)
	}
}

func TestCriticalRuntimePinning(t *testing.T) {
	path := filepath.Clean(filepath.Join("..", "..", "policy", "examples", "critical-runtime-pinning.yaml"))
	sources, err := LoadSources([]string{path})
	if err != nil {
		t.Fatalf("LoadSources: %v", err)
	}
	pkg := &dependencyv1.Package{Name: "golang.org/x/crypto", Version: "v0.24.0", Ecosystem: "go"}
	payload := map[string]any{
		"change": map[string]any{
			"base_version":   "v0.24.0",
			"target_version": "v0.24.0",
		},
		"pkg": pkg,
		"env": &policyv1.Environment{Command: "diff", Entrypoint: "diff_dependency_change"},
	}
	if actions, err := EvaluateMap(t.Context(), sources, payload); err != nil {
		t.Fatalf("EvaluateAll: %v", err)
	} else {
		warn := false
		for _, a := range actions {
			if a.Type == "warn" {
				warn = true
			}
		}
		if !warn {
			t.Fatalf("expected warn for unchanged critical module, got %+v", actions)
		}
	}
}

func TestSbomSizeShapeSanity(t *testing.T) {
	path := filepath.Clean(filepath.Join("..", "..", "policy", "examples", "sbom-size-shape-sanity.yaml"))
	sources, err := LoadSources([]string{path})
	if err != nil {
		t.Fatalf("LoadSources: %v", err)
	}
	components := make([]any, 12000)
	payload := map[string]any{
		"packages": components,
		"env":      &policyv1.Environment{Command: "sbom", Entrypoint: "sbom_report"},
	}
	if actions, err := EvaluateMap(t.Context(), sources, payload); err != nil {
		t.Fatalf("EvaluateAll: %v", err)
	} else {
		warn := false
		for _, a := range actions {
			if a.Type == "warn" {
				warn = true
			}
		}
		if !warn {
			t.Fatalf("expected warn for oversized SBOM, got %+v", actions)
		}
	}
}
func TestExploitAvailableBlocker(t *testing.T) {
	path := filepath.Clean(filepath.Join("..", "..", "policy", "examples", "exploit-available-blocker.yaml"))
	sources, err := LoadSources([]string{path})
	if err != nil {
		t.Fatalf("LoadSources: %v", err)
	}

	t.Run("deny when exploit referenced", func(t *testing.T) {
		payload := map[string]any{
			"vulnerability": &vulnerabilityv1.Finding{
				Advisory: &vulnerabilityv1.Advisory{
					References: []string{"https://exploit-db.com/poc"},
					Severity: &vulnerabilityv1.Severity{
						Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_HIGH,
					},
				},
			},
			"env": &policyv1.Environment{Command: "scan", Entrypoint: "scan_vulnerability"},
		}
		actions, err := EvaluateMap(t.Context(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		deny := false
		for _, a := range actions {
			if a.Type == "deny" {
				deny = true
			}
		}
		if !deny {
			t.Fatalf("expected deny when exploit reference present, got %+v", actions)
		}
	})

	t.Run("allow when no exploit indicators", func(t *testing.T) {
		payload := map[string]any{
			"vulnerability": &vulnerabilityv1.Finding{
				Advisory: &vulnerabilityv1.Advisory{
					References: []string{"https://advisory.example.com"},
					Severity: &vulnerabilityv1.Severity{
						Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_HIGH,
					},
				},
			},
			"env": &policyv1.Environment{Command: "scan", Entrypoint: "scan_vulnerability"},
		}
		actions, err := EvaluateMap(t.Context(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		for _, a := range actions {
			if a.Type == "deny" {
				t.Fatalf("did not expect deny without exploit: %+v", actions)
			}
		}
	})
}

func TestDeprecatedModuleBlock(t *testing.T) {
	path := filepath.Clean(filepath.Join("..", "..", "policy", "examples", "deprecated-module-block.yaml"))
	sources, err := LoadSources([]string{path})
	if err != nil {
		t.Fatalf("LoadSources: %v", err)
	}

	t.Run("deny deprecated in summary", func(t *testing.T) {
		payload := map[string]any{
			"vulnerability": &vulnerabilityv1.Finding{
				Advisory: &vulnerabilityv1.Advisory{
					Summary: "Package deprecated and no longer maintained",
				},
			},
			"env": &policyv1.Environment{Command: "scan", Entrypoint: "scan_vulnerability"},
		}
		actions, err := EvaluateMap(t.Context(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		deny := false
		for _, a := range actions {
			if a.Type == "deny" {
				deny = true
			}
		}
		if !deny {
			t.Fatalf("expected deny for deprecated summary, got %+v", actions)
		}
	})

	t.Run("allow when not deprecated", func(t *testing.T) {
		payload := map[string]any{
			"vulnerability": &vulnerabilityv1.Finding{
				Advisory: &vulnerabilityv1.Advisory{
					Summary: "Buffer overflow in parser",
				},
			},
			"env": &policyv1.Environment{Command: "scan", Entrypoint: "scan_vulnerability"},
		}
		actions, err := EvaluateMap(t.Context(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		for _, a := range actions {
			if a.Type == "deny" {
				t.Fatalf("did not expect deny for non-deprecated issue: %+v", actions)
			}
		}
	})
}

func TestBlockPackagePolicy(t *testing.T) {
	path := filepath.Clean(filepath.Join("..", "..", "policy", "examples", "block-package.yaml"))
	sources, err := LoadSources([]string{path})
	if err != nil {
		t.Fatalf("LoadSources: %v", err)
	}
	payload := map[string]any{
		"pkg": &dependencyv1.Package{Name: "left-pad"},
		"env": &policyv1.Environment{Command: "proxy"},
	}
	actions, err := EvaluateMap(t.Context(), sources, payload)
	if err != nil {
		t.Fatalf("EvaluateAll: %v", err)
	}
	if len(actions) == 0 || actions[0].Type != "deny" {
		t.Fatalf("expected deny for blocked package, got %+v", actions)
	}
}

func TestGoDowngradeGuard(t *testing.T) {
	path := filepath.Clean(filepath.Join("..", "..", "policy", "examples", "go-downgrade-guard.yaml"))
	sources, err := LoadSources([]string{path})
	if err != nil {
		t.Fatalf("LoadSources: %v", err)
	}
	pkg := &dependencyv1.Package{Name: "golang.org/x/net", Ecosystem: "go"}
	denyPayload := map[string]any{
		"change": map[string]any{
			"type": "downgraded",
		},
		"pkg": pkg,
		"env": &policyv1.Environment{Command: "diff", Entrypoint: "diff_dependency_change"},
	}
	if actions, err := EvaluateMap(t.Context(), sources, denyPayload); err != nil || len(actions) == 0 || actions[0].Type != "deny" {
		t.Fatalf("expected deny for go downgrade, got %+v err=%v", actions, err)
	}
	allowPayload := map[string]any{
		"change": map[string]any{
			"type": "upgraded",
		},
		"pkg": pkg,
		"env": &policyv1.Environment{Command: "diff", Entrypoint: "diff_dependency_change"},
	}
	if actions, err := EvaluateMap(t.Context(), sources, allowPayload); err != nil {
		t.Fatalf("EvaluateAll: %v", err)
	} else {
		for _, a := range actions {
			if a.Type == "deny" {
				t.Fatalf("did not expect deny for upgrade: %+v", actions)
			}
		}
	}
}

func TestLicenseAllowlistAdvisory(t *testing.T) {
	path := filepath.Clean(filepath.Join("..", "..", "policy", "examples", "license-allowlist-advisory.yaml"))
	sources, err := LoadSources([]string{path})
	if err != nil {
		t.Fatalf("LoadSources: %v", err)
	}
	payload := map[string]any{
		"pkg": &dependencyv1.Package{Licenses: []string{"AGPL-3.0"}},
		"env": &policyv1.Environment{Command: "proxy"},
	}
	actions, err := EvaluateMap(t.Context(), sources, payload)
	if err != nil {
		t.Fatalf("EvaluateAll: %v", err)
	}
	warn := false
	for _, a := range actions {
		if a.Type == "warn" {
			warn = true
		}
		if a.Type == "deny" {
			t.Fatalf("advisory policy should downgrade deny to warn: %+v", actions)
		}
	}
	if !warn {
		t.Fatalf("expected warn for forbidden license in advisory mode, got %+v", actions)
	}
}

func TestLog4ShellPolicy(t *testing.T) {
	path := filepath.Clean(filepath.Join("..", "..", "policy", "examples", "log4shell.yaml"))
	sources, err := LoadSources([]string{path})
	if err != nil {
		t.Fatalf("LoadSources: %v", err)
	}

	payload := map[string]any{
		"vulnerabilities": []*vulnerabilityv1.Finding{
			{
				Advisory: &vulnerabilityv1.Advisory{
					Aliases: []string{"CVE-2021-44228"},
				},
			},
		},
	}
	actions, err := EvaluateMap(t.Context(), sources, payload)
	if err != nil {
		t.Fatalf("EvaluateAll: %v", err)
	}
	if len(actions) == 0 || actions[0].Type != "deny" {
		t.Fatalf("expected deny for log4shell alias, got %+v", actions)
	}
}

func TestMinVersionPolicy(t *testing.T) {
	path := filepath.Clean(filepath.Join("..", "..", "policy", "examples", "min-version.yaml"))
	sources, err := LoadSources([]string{path})
	if err != nil {
		t.Fatalf("LoadSources: %v", err)
	}
	payload := map[string]any{
		"pkg": &dependencyv1.Package{
			Ecosystem: "go",
			Name:      "golang.org/x/crypto",
			Version:   "v0.25.0",
		},
	}
	actions, err := EvaluateMap(t.Context(), sources, payload)
	if err != nil {
		t.Fatalf("EvaluateAll: %v", err)
	}
	if len(actions) == 0 || actions[0].Type != "deny" {
		t.Fatalf("expected deny for version below baseline, got %+v", actions)
	}
}

func TestNpmScopeAllowlist(t *testing.T) {
	path := filepath.Clean(filepath.Join("..", "..", "policy", "examples", "npm-scope-allowlist.yaml"))
	sources, err := LoadSources([]string{path})
	if err != nil {
		t.Fatalf("LoadSources: %v", err)
	}
	denyPayload := map[string]any{
		"pkg": &dependencyv1.Package{
			Ecosystem: "npm",
			Name:      "evilpkg",
		},
		"env": &policyv1.Environment{Command: "proxy", Entrypoint: "npm_artifact_request"},
	}
	if actions, err := EvaluateMap(t.Context(), sources, denyPayload); err != nil || len(actions) == 0 || actions[0].Type != "deny" {
		t.Fatalf("expected deny for unapproved npm package, got %+v err=%v", actions, err)
	}
	allowPayload := map[string]any{
		"pkg": &dependencyv1.Package{
			Ecosystem: "npm",
			Name:      "lodash",
		},
		"env": &policyv1.Environment{Command: "proxy", Entrypoint: "npm_artifact_request"},
	}
	if actions, err := EvaluateMap(t.Context(), sources, allowPayload); err != nil {
		t.Fatalf("EvaluateAll: %v", err)
	} else {
		for _, a := range actions {
			if a.Type == "deny" {
				t.Fatalf("did not expect deny for allowlisted package: %+v", actions)
			}
		}
	}
}

func TestProxyCriticalAdvisory(t *testing.T) {
	path := filepath.Clean(filepath.Join("..", "..", "policy", "examples", "proxy-critical-advisory.yaml"))
	sources, err := LoadSources([]string{path})
	if err != nil {
		t.Fatalf("LoadSources: %v", err)
	}

	payload := map[string]any{
		"vulnerabilities": []*vulnerabilityv1.Finding{
			{
				Advisory: &vulnerabilityv1.Advisory{
					Severity: &vulnerabilityv1.Severity{
						Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_CRITICAL,
					},
				},
			},
		},
		"env": &policyv1.Environment{Command: "proxy", Entrypoint: "go_artifact_request"},
	}
	actions, err := EvaluateMap(t.Context(), sources, payload)
	if err != nil {
		t.Fatalf("EvaluateAll: %v", err)
	}
	warn := false
	for _, a := range actions {
		if a.Type == "warn" {
			warn = true
		}
		if a.Type == "deny" {
			t.Fatalf("advisory policy should downgrade to warn: %+v", actions)
		}
	}
	if !warn {
		t.Fatalf("expected warn for critical vuln at proxy, got %+v", actions)
	}
}

func TestRuntimeCriticalBaseline(t *testing.T) {
	path := filepath.Clean(filepath.Join("..", "..", "policy", "examples", "runtime-critical-baseline.yaml"))
	sources, err := LoadSources([]string{path})
	if err != nil {
		t.Fatalf("LoadSources: %v", err)
	}
	pkg := &dependencyv1.Package{Name: "github.com/google/uuid", Ecosystem: "go"}
	payload := map[string]any{
		"change": map[string]any{
			"type": "removed",
		},
		"pkg": pkg,
		"env": &policyv1.Environment{Command: "diff", Entrypoint: "diff_dependency_change"},
	}
	actions, err := EvaluateMap(t.Context(), sources, payload)
	if err != nil {
		t.Fatalf("EvaluateAll: %v", err)
	}
	if len(actions) == 0 || actions[0].Type != "deny" {
		t.Fatalf("expected deny for removing critical runtime dep, got %+v", actions)
	}
}

func TestSeverityGuardrail(t *testing.T) {
	path := filepath.Clean(filepath.Join("..", "..", "policy", "examples", "severity-guardrail.yaml"))
	sources, err := LoadSources([]string{path})
	if err != nil {
		t.Fatalf("LoadSources: %v", err)
	}
	// Use proto Finding messages
	payload := map[string]any{
		"vulnerabilities": []*vulnerabilityv1.Finding{
			{
				Advisory: &vulnerabilityv1.Advisory{
					Severity: &vulnerabilityv1.Severity{
						Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_HIGH,
					},
				},
			},
		},
		"env": &policyv1.Environment{Command: "scan", Entrypoint: "scan_vulnerability"},
	}
	actions, err := EvaluateMap(t.Context(), sources, payload)
	if err != nil {
		t.Fatalf("EvaluateAll: %v", err)
	}
	if len(actions) == 0 || actions[0].Type != "deny" {
		t.Fatalf("expected deny for high severity vuln, got %+v", actions)
	}
}

func TestShaiHuludNpm(t *testing.T) {
	path := filepath.Clean(filepath.Join("..", "..", "policy", "examples", "shai-hulud-npm.yaml"))
	sources, err := LoadSources([]string{path})
	if err != nil {
		t.Fatalf("LoadSources: %v", err)
	}
	payload := map[string]any{
		"pkg": &dependencyv1.Package{
			Ecosystem: "npm",
			Name:      "@kvytech/cli",
			Version:   "0.0.7",
		},
		"env": &policyv1.Environment{Command: "proxy", Entrypoint: "npm_artifact_request"},
	}
	actions, err := EvaluateMap(t.Context(), sources, payload)
	if err != nil {
		t.Fatalf("EvaluateAll: %v", err)
	}
	if len(actions) == 0 || actions[0].Type != "deny" {
		t.Fatalf("expected deny for IOC package, got %+v", actions)
	}
}

func TestXZBackdoorPolicy(t *testing.T) {
	path := filepath.Clean(filepath.Join("..", "..", "policy", "examples", "xz-backdoor.yaml"))
	sources, err := LoadSources([]string{path})
	if err != nil {
		t.Fatalf("LoadSources: %v", err)
	}
	payload := map[string]any{
		"pkg": &dependencyv1.Package{
			Ecosystem: "npm",
			Name:      "xz",
			Version:   "5.6.0",
		},
		"env": &policyv1.Environment{Command: "proxy"},
	}
	actions, err := EvaluateMap(t.Context(), sources, payload)
	if err != nil {
		t.Fatalf("EvaluateAll: %v", err)
	}
	if len(actions) == 0 || actions[0].Type != "deny" {
		t.Fatalf("expected deny for compromised xz version, got %+v", actions)
	}
}
