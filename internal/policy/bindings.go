// Package policy provides CEL-based policy evaluation for Deputy.
//
// This file defines the variable bindings available at each policy entrypoint.
// These bindings document the contract between policy authors and the runtime.

package policy

// BindingProfile describes the variables available at a specific entrypoint.
// This enables compile-time documentation and runtime validation of policy contexts.
type BindingProfile struct {
	// Entrypoint is the canonical entrypoint this profile applies to.
	Entrypoint Entrypoint

	// Required lists variables that are always available at this entrypoint.
	// Policy authors can rely on these without null checks.
	Required []string

	// Optional lists variables that may be available depending on context.
	// Policy authors should use CEL optional syntax (?.field.orValue()) for these.
	Optional []string

	// Description briefly explains when this entrypoint triggers.
	Description string
}

// Variables returns all variable names (required + optional) for this profile.
func (p BindingProfile) Variables() []string {
	result := make([]string, 0, len(p.Required)+len(p.Optional))
	result = append(result, p.Required...)
	result = append(result, p.Optional...)
	return result
}

// IsRequired reports whether the named variable is always available.
func (p BindingProfile) IsRequired(name string) bool {
	for _, v := range p.Required {
		if v == name {
			return true
		}
	}
	return false
}

// Common variable groups - reusable across entrypoints
var (
	// envVars are always available
	envVars = []string{"env"}

	// jwtVars are available in proxy contexts
	jwtVars = []string{"jwt"}

	// vulnerabilityListVars provide access to vulnerability collections
	vulnerabilityListVars = []string{"vulnerabilities", "findings"}

	// singleVulnerabilityVars provide access to a single vulnerability
	singleVulnerabilityVars = []string{"vulnerability", "pkg"}

	// imageVars provide container image information
	imageVars = []string{"image", "image_info"}

	// targetVars provide target/provenance information
	targetVars = []string{"target"}

	// dockerfileVars provide Dockerfile analysis
	dockerfileVars = []string{"dockerfile", "dockerfile_analysis"}

	// containerDiffVars provide container comparison data
	containerDiffVars = []string{
		"base_image", "target_image",
		"package_changes", "vulnerability_changes",
		"config_changes", "layer_analysis", "summary",
	}
)

// BindingProfiles maps each entrypoint to its variable bindings.
// This is the authoritative source for what's available where.
var BindingProfiles = map[Entrypoint]BindingProfile{
	// Proxy entrypoints
	EntrypointGoArtifactRequest: {
		Entrypoint:  EntrypointGoArtifactRequest,
		Required:    []string{"request", "env"},
		Optional:    append([]string{"vulnerabilities", "licenses"}, jwtVars...),
		Description: "Triggers when the proxy handles a Go module request",
	},
	EntrypointNpmArtifactRequest: {
		Entrypoint:  EntrypointNpmArtifactRequest,
		Required:    []string{"request", "env"},
		Optional:    append([]string{"vulnerabilities", "licenses"}, jwtVars...),
		Description: "Triggers when the proxy handles an NPM package request",
	},
	EntrypointPypiArtifactRequest: {
		Entrypoint:  EntrypointPypiArtifactRequest,
		Required:    []string{"request", "env"},
		Optional:    append([]string{"vulnerabilities", "licenses"}, jwtVars...),
		Description: "Triggers when the proxy handles a PyPI package request",
	},
	EntrypointRubygemsArtifactRequest: {
		Entrypoint:  EntrypointRubygemsArtifactRequest,
		Required:    []string{"request", "env"},
		Optional:    append([]string{"vulnerabilities", "licenses"}, jwtVars...),
		Description: "Triggers when the proxy handles a RubyGems package request",
	},
	EntrypointOCIArtifactRequest: {
		Entrypoint:  EntrypointOCIArtifactRequest,
		Required:    []string{"request", "env"},
		Optional:    append(append([]string{"vulnerabilities"}, imageVars...), jwtVars...),
		Description: "Triggers when the proxy handles an OCI image request",
	},

	// Scan entrypoints
	EntrypointScanReport: {
		Entrypoint:  EntrypointScanReport,
		Required:    append([]string{"vulnerabilities", "packages"}, envVars...),
		Optional:    append(targetVars, imageVars...),
		Description: "Triggers after a scan completes with the full report",
	},
	EntrypointScanVulnerability: {
		Entrypoint:  EntrypointScanVulnerability,
		Required:    append(singleVulnerabilityVars, envVars...),
		Optional:    append(targetVars, imageVars...),
		Description: "Triggers for each vulnerability found during a scan",
	},

	// Diff entrypoints (git repository)
	EntrypointDiffReport: {
		Entrypoint:  EntrypointDiffReport,
		Required:    append([]string{"changes", "vulnerabilities"}, envVars...),
		Optional:    targetVars,
		Description: "Triggers after a dependency diff completes",
	},
	EntrypointDiffDependencyChange: {
		Entrypoint:  EntrypointDiffDependencyChange,
		Required:    append([]string{"change", "dependency"}, envVars...),
		Optional:    targetVars,
		Description: "Triggers for each dependency change in a diff",
	},
	EntrypointDiffVulnerability: {
		Entrypoint:  EntrypointDiffVulnerability,
		Required:    append(singleVulnerabilityVars, envVars...),
		Optional:    targetVars,
		Description: "Triggers for each vulnerability found in a diff",
	},

	// Container diff entrypoints
	EntrypointContainerDiffReport: {
		Entrypoint:  EntrypointContainerDiffReport,
		Required:    append(containerDiffVars, envVars...),
		Optional:    nil,
		Description: "Triggers after a container image diff completes",
	},
	EntrypointContainerDiffChange: {
		Entrypoint:  EntrypointContainerDiffChange,
		Required:    append([]string{"change"}, envVars...),
		Optional:    []string{"base_image", "target_image"},
		Description: "Triggers for each package change between container images",
	},
	EntrypointContainerDiffVulnerability: {
		Entrypoint:  EntrypointContainerDiffVulnerability,
		Required:    append(singleVulnerabilityVars, envVars...),
		Optional:    []string{"base_image", "target_image"},
		Description: "Triggers for each vulnerability difference between images",
	},
	EntrypointContainerDiffLayer: {
		Entrypoint:  EntrypointContainerDiffLayer,
		Required:    append([]string{"layer"}, envVars...),
		Optional:    []string{"base_image", "target_image"},
		Description: "Triggers for each layer difference analysis",
	},
	EntrypointContainerDiffConfig: {
		Entrypoint:  EntrypointContainerDiffConfig,
		Required:    append([]string{"config_changes"}, envVars...),
		Optional:    []string{"base_image", "target_image"},
		Description: "Triggers for configuration changes between images",
	},

	// SBOM entrypoints
	EntrypointSBOMReport: {
		Entrypoint:  EntrypointSBOMReport,
		Required:    append([]string{"sbom", "packages"}, envVars...),
		Optional:    targetVars,
		Description: "Triggers after an SBOM is generated",
	},
	EntrypointSBOMComponent: {
		Entrypoint:  EntrypointSBOMComponent,
		Required:    append([]string{"component", "pkg"}, envVars...),
		Optional:    nil,
		Description: "Triggers for each component in an SBOM",
	},

	// Fix entrypoints
	EntrypointFixPlan: {
		Entrypoint:  EntrypointFixPlan,
		Required:    append([]string{"plan"}, envVars...),
		Optional:    []string{"vulnerabilities", "repo"},
		Description: "Triggers after a remediation plan is generated",
	},
	EntrypointFixPlanStep: {
		Entrypoint:  EntrypointFixPlanStep,
		Required:    append([]string{"step"}, envVars...),
		Optional:    []string{"plan"},
		Description: "Triggers for each step in a remediation plan",
	},

	// Triage entrypoints
	EntrypointTriageReport: {
		Entrypoint:  EntrypointTriageReport,
		Required:    append([]string{"findings", "vulnerabilities"}, envVars...),
		Optional:    []string{"repo"},
		Description: "Triggers after a triage report is generated",
	},
	EntrypointTriageCluster: {
		Entrypoint:  EntrypointTriageCluster,
		Required:    append([]string{"cluster"}, envVars...),
		Optional:    nil,
		Description: "Triggers for each cluster in a triage report",
	},

	// Dockerfile entrypoints
	EntrypointDockerfileReport: {
		Entrypoint:  EntrypointDockerfileReport,
		Required:    append(dockerfileVars, envVars...),
		Optional:    targetVars,
		Description: "Triggers after a Dockerfile is parsed",
	},
	EntrypointDockerfileStage: {
		Entrypoint:  EntrypointDockerfileStage,
		Required:    append([]string{"stage"}, envVars...),
		Optional:    dockerfileVars,
		Description: "Triggers for each stage in a multi-stage Dockerfile",
	},
}

// GetBindingProfile returns the binding profile for an entrypoint.
// Returns nil if the entrypoint is not recognized.
func GetBindingProfile(ep Entrypoint) *BindingProfile {
	if profile, ok := BindingProfiles[ep]; ok {
		return &profile
	}
	return nil
}

// VariablesForEntrypoint returns all variables available at the given entrypoint.
// This is useful for LSP autocompletion and documentation generation.
func VariablesForEntrypoint(ep Entrypoint) []string {
	if profile := GetBindingProfile(ep); profile != nil {
		return profile.Variables()
	}
	// Fallback to all default variables for unknown entrypoints
	return DefaultVariableNames()
}

// RequiredVariablesForEntrypoint returns variables that are always available.
func RequiredVariablesForEntrypoint(ep Entrypoint) []string {
	if profile := GetBindingProfile(ep); profile != nil {
		return profile.Required
	}
	return nil
}

// OptionalVariablesForEntrypoint returns variables that may be available.
func OptionalVariablesForEntrypoint(ep Entrypoint) []string {
	if profile := GetBindingProfile(ep); profile != nil {
		return profile.Optional
	}
	return nil
}
