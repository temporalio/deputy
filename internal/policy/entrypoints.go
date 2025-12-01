package policy

// Canonical entrypoint names emitted by Deputy commands. Keep in sync with CLI/proxy emitters.

const (
	EntrypointGoArtifactRequest       = "go_artifact_request"
	EntrypointNpmArtifactRequest      = "npm_artifact_request"
	EntrypointPypiArtifactRequest     = "pypi_artifact_request"
	EntrypointRubygemsArtifactRequest = "rubygems_artifact_request"

	EntrypointScanReport        = "scan_report"
	EntrypointScanVulnerability = "scan_vulnerability"

	EntrypointDiffReport           = "diff_report"
	EntrypointDiffDependencyChange = "diff_dependency_change"
	EntrypointDiffVulnerability    = "diff_vulnerability"

	EntrypointSBOMReport    = "sbom_report"
	EntrypointSBOMComponent = "sbom_component"

	EntrypointFixPlan     = "fix_plan"
	EntrypointFixPlanStep = "fix_plan_step"

	EntrypointTriageReport  = "triage_report"
	EntrypointTriageCluster = "triage_cluster"
)

var (
	EntrypointsProxy = []string{
		EntrypointGoArtifactRequest,
		EntrypointNpmArtifactRequest,
		EntrypointPypiArtifactRequest,
		EntrypointRubygemsArtifactRequest,
	}
	EntrypointsScan = []string{
		EntrypointScanReport,
		EntrypointScanVulnerability,
	}
	EntrypointsDiff = []string{
		EntrypointDiffReport,
		EntrypointDiffDependencyChange,
		EntrypointDiffVulnerability,
	}
	EntrypointsSBOM = []string{
		EntrypointSBOMReport,
		EntrypointSBOMComponent,
	}
	EntrypointsFix = []string{
		EntrypointFixPlan,
		EntrypointFixPlanStep,
	}
	EntrypointsTriage = []string{
		EntrypointTriageReport,
		EntrypointTriageCluster,
	}

	AllEntrypoints = append(append(append(append(append(append([]string{}, EntrypointsProxy...), EntrypointsScan...), EntrypointsDiff...), EntrypointsSBOM...), EntrypointsFix...), EntrypointsTriage...)

	allowedEntrypointsSet = buildSet(AllEntrypoints)
	allowedCommands       = []string{"proxy", "scan", "diff", "sbom", "fix", "triage"}
	allowedCommandsSet    = buildSet(allowedCommands)
)

func buildSet(items []string) map[string]struct{} {
	m := make(map[string]struct{}, len(items))
	for _, v := range items {
		m[v] = struct{}{}
	}
	return m
}

// IsAllowedEntrypoint reports whether the name matches a canonical entrypoint.
func IsAllowedEntrypoint(name string) bool {
	_, ok := allowedEntrypointsSet[name]
	return ok
}

// IsAllowedCommand reports whether the command is one of the known CLI/proxy commands.
func IsAllowedCommand(cmd string) bool {
	_, ok := allowedCommandsSet[cmd]
	return ok
}
