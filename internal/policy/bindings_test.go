package policy

import (
	"slices"
	"testing"
)

func TestAllEntrypointsHaveBindings(t *testing.T) {
	for _, ep := range AllEntrypoints {
		if GetBindingProfile(ep) == nil {
			t.Errorf("entrypoint %q has no binding profile", ep)
		}
	}
}

func TestBindingProfilesHaveEntrypoints(t *testing.T) {
	for ep := range BindingProfiles {
		if !ep.IsValid() {
			t.Errorf("binding profile for %q references unknown entrypoint", ep)
		}
	}
}

func TestBindingProfilesHaveDescriptions(t *testing.T) {
	for ep, profile := range BindingProfiles {
		if profile.Description == "" {
			t.Errorf("binding profile for %q has no description", ep)
		}
	}
}

func TestBindingProfilesHaveEnvVar(t *testing.T) {
	for ep, profile := range BindingProfiles {
		vars := profile.Variables()
		if !slices.Contains(vars, "env") {
			t.Errorf("binding profile for %q missing 'env' variable", ep)
		}
	}
}

func TestVariablesForEntrypoint(t *testing.T) {
	tests := []struct {
		entrypoint Entrypoint
		mustHave   []string
	}{
		{
			entrypoint: EntrypointScanVulnerability,
			mustHave:   []string{"vulnerability", "pkg", "env"},
		},
		{
			entrypoint: EntrypointScanReport,
			mustHave:   []string{"vulnerabilities", "packages", "env"},
		},
		{
			entrypoint: EntrypointGoArtifactRequest,
			mustHave:   []string{"request", "env"},
		},
		{
			entrypoint: EntrypointDockerfileReport,
			mustHave:   []string{"dockerfile", "dockerfile_analysis", "env"},
		},
	}

	for _, tt := range tests {
		t.Run(string(tt.entrypoint), func(t *testing.T) {
			vars := VariablesForEntrypoint(tt.entrypoint)
			for _, want := range tt.mustHave {
				if !slices.Contains(vars, want) {
					t.Errorf("entrypoint %q missing expected variable %q", tt.entrypoint, want)
				}
			}
		})
	}
}

func TestRequiredVsOptional(t *testing.T) {
	for ep, profile := range BindingProfiles {
		// Check no overlap between required and optional
		for _, req := range profile.Required {
			if slices.Contains(profile.Optional, req) {
				t.Errorf("entrypoint %q has %q in both required and optional", ep, req)
			}
		}
	}
}

func TestBindingProfileVariables(t *testing.T) {
	profile := BindingProfiles[EntrypointScanVulnerability]
	vars := profile.Variables()

	// Should include both required and optional
	if !slices.Contains(vars, "vulnerability") {
		t.Error("expected 'vulnerability' in variables")
	}
	if !slices.Contains(vars, "env") {
		t.Error("expected 'env' in variables")
	}

	// IsRequired should work
	if !profile.IsRequired("vulnerability") {
		t.Error("expected 'vulnerability' to be required")
	}
	if profile.IsRequired("target") {
		t.Error("expected 'target' to be optional, not required")
	}
}

func TestExampleCategoriesCoverAllEntrypoints(t *testing.T) {
	seen := make(map[Entrypoint]string)
	for _, cat := range ExampleCategories {
		for _, ep := range cat.Entrypoints {
			if ep.Category() != cat.Name {
				t.Errorf("entrypoint %q is in category %q, want %q", ep, cat.Name, ep.Category())
			}
			if prev, ok := seen[ep]; ok {
				t.Errorf("entrypoint %q appears in both %q and %q", ep, prev, cat.Name)
			}
			seen[ep] = cat.Name
		}
	}

	for _, ep := range AllEntrypoints {
		if _, ok := seen[ep]; !ok {
			t.Errorf("entrypoint %q missing from ExampleCategories", ep)
		}
	}
}
