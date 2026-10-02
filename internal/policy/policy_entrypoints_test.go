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
		// The policy has no command scoping, so the missing-license warn rule
		// fires for scan payloads too; the deny rule must not.
		if len(actions) != 1 || actions[0].Type != "warn" {
			t.Fatalf("expected one warn action for scan payload, got %+v", actions)
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
		// Permissive licenses match neither the deny rule nor the
		// missing-license warn rule, so no actions may fire at all.
		if len(actions) != 0 {
			t.Fatalf("expected no actions for permissive license, got %+v", actions)
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
		// The policy's only rule is the v1 deny; v2 must produce zero actions.
		if len(actions) != 0 {
			t.Fatalf("expected no actions for v2, got %+v", actions)
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
		// The policy's only rule is the org-allowlist deny; an approved org
		// must produce zero actions.
		if len(actions) != 0 {
			t.Fatalf("expected no actions for approved org, got %+v", actions)
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
		// The policy's only rule is the pseudo-version deny; a tagged release
		// must produce zero actions.
		if len(actions) != 0 {
			t.Fatalf("expected no actions for tagged release, got %+v", actions)
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
		// The policy's only rule is the pre-release deny; a stable release
		// must produce zero actions.
		if len(actions) != 0 {
			t.Fatalf("expected no actions for stable release, got %+v", actions)
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
		// The policy's only rule denies HIGH/CRITICAL with a fix; a medium
		// severity vulnerability must produce zero actions.
		if len(actions) != 0 {
			t.Fatalf("expected no actions for medium severity, got %+v", actions)
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
		// The policy's only rule is the unapproved-addition deny; an approved
		// prefix must produce zero actions.
		if len(actions) != 0 {
			t.Fatalf("expected no actions for approved addition, got %+v", actions)
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
		// The policy's only rule is the command-allowlist deny; a vetted
		// command must produce zero actions.
		if len(actions) != 0 {
			t.Fatalf("expected no actions for allowed command, got %+v", actions)
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
		// The policy's only rule is the missing-metadata warn; complete
		// metadata must produce zero actions.
		if len(actions) != 0 {
			t.Fatalf("expected no actions for complete metadata, got %+v", actions)
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
		// The policy's only rule is the unstable-version warn; a stable
		// version must produce zero actions.
		if len(actions) != 0 {
			t.Fatalf("expected no actions for stable version, got %+v", actions)
		}
	})
}

// TestPypiPrefixAllowlist exercises the shipped prefix allowlist against the
// spellings PyPI accepts for one distribution. The prefixes are written in PEP
// 503 form because that is the form a package name reaches a policy in, so an
// approved distribution must be allowed however the request spelled it and an
// unapproved one must be denied the same way.
func TestPypiPrefixAllowlist(t *testing.T) {
	path := filepath.Clean(filepath.Join("..", "..", "policy", "examples", "pypi-prefix-allowlist.yaml"))
	sources, err := LoadSources([]string{path})
	if err != nil {
		t.Fatalf("LoadSources: %v", err)
	}

	tests := []struct {
		name     string
		pkgName  string
		wantDeny bool
	}{
		{name: "unapproved prefix", pkgName: "randompkg", wantDeny: true},
		{name: "unapproved prefix with separator", pkgName: "random_pkg", wantDeny: true},
		{name: "approved prefix underscore spelling", pkgName: "acme_toolkit"},
		{name: "approved prefix hyphen spelling", pkgName: "acme-toolkit"},
		{name: "approved prefix dot spelling", pkgName: "acme.toolkit"},
		{name: "approved prefix mixed case", pkgName: "Corp_Toolkit"},
		{name: "approved hyphen-only prefix", pkgName: "internal-toolkit"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := map[string]any{
				"pkg": &dependencyv1.Package{
					Name:      tt.pkgName,
					Ecosystem: "pypi",
				},
				"request": &policyv1.ProxyRequest{
					Ecosystem: "pypi",
					Package:   tt.pkgName,
				},
				"env": &policyv1.Environment{Command: "proxy", Entrypoint: "pypi_artifact_request"},
			}
			actions, err := EvaluateMap(t.Context(), sources, payload)
			if err != nil {
				t.Fatalf("EvaluateMap: %v", err)
			}
			deny := slices.ContainsFunc(actions, func(a Action) bool { return a.Type == "deny" })
			if deny != tt.wantDeny {
				t.Fatalf("deny = %t for %q, want %t; actions %+v", deny, tt.pkgName, tt.wantDeny, actions)
			}
		})
	}
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
	} else if len(actions) != 0 {
		// The policy's only rule is the missing-license deny; present license
		// metadata must produce zero actions.
		t.Fatalf("expected no actions for present license metadata, got %+v", actions)
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
		// The policy's only rule is the exploit-indicator deny; a plain
		// advisory reference must produce zero actions.
		if len(actions) != 0 {
			t.Fatalf("expected no actions without exploit indicators, got %+v", actions)
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
		// The policy's only rule is the deprecated-text deny; a non-deprecated
		// summary must produce zero actions.
		if len(actions) != 0 {
			t.Fatalf("expected no actions for non-deprecated issue, got %+v", actions)
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
	} else if len(actions) != 0 {
		// The policy's only rule is the downgrade deny; an upgrade must
		// produce zero actions.
		t.Fatalf("expected no actions for upgrade, got %+v", actions)
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
	} else if len(actions) != 0 {
		// lodash is allowlisted and not an @acme pre-release, so neither the
		// deny nor the warn rule may fire.
		t.Fatalf("expected no actions for allowlisted package, got %+v", actions)
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
