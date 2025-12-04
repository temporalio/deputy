package policy

// Canonical entrypoint names emitted by Deputy commands. Keep in sync with CLI/proxy emitters.

const (
	// EntrypointGoArtifactRequest triggers when the proxy handles a Go module request.
	EntrypointGoArtifactRequest = "go_artifact_request"
	// EntrypointNpmArtifactRequest triggers when the proxy handles an NPM package request.
	EntrypointNpmArtifactRequest = "npm_artifact_request"
	// EntrypointPypiArtifactRequest triggers when the proxy handles a PyPI package request.
	EntrypointPypiArtifactRequest = "pypi_artifact_request"
	// EntrypointRubygemsArtifactRequest triggers when the proxy handles a RubyGems package request.
	EntrypointRubygemsArtifactRequest = "rubygems_artifact_request"

	// EntrypointScanReport triggers after a scan completes, providing the full report.
	EntrypointScanReport = "scan_report"
	// EntrypointScanVulnerability triggers for each vulnerability found during a scan.
	EntrypointScanVulnerability = "scan_vulnerability"

	// EntrypointDiffReport triggers after a diff completes, providing the full report.
	EntrypointDiffReport = "diff_report"
	// EntrypointDiffDependencyChange triggers for each dependency change found during a diff.
	EntrypointDiffDependencyChange = "diff_dependency_change"
	// EntrypointDiffVulnerability triggers for each vulnerability found during a diff.
	EntrypointDiffVulnerability = "diff_vulnerability"

	// EntrypointSBOMReport triggers after an SBOM is generated.
	EntrypointSBOMReport = "sbom_report"
	// EntrypointSBOMComponent triggers for each component in an SBOM.
	EntrypointSBOMComponent = "sbom_component"

	// EntrypointFixPlan triggers after a remediation plan is generated.
	EntrypointFixPlan = "fix_plan"
	// EntrypointFixPlanStep triggers for each step in a remediation plan.
	EntrypointFixPlanStep = "fix_plan_step"

	// EntrypointTriageReport triggers after a triage report is generated.
	EntrypointTriageReport = "triage_report"
	// EntrypointTriageCluster triggers for each cluster of issues in a triage report.
	EntrypointTriageCluster = "triage_cluster"
)

var (
	// EntrypointsProxy lists all entrypoints related to the artifact proxy.
	EntrypointsProxy = []string{
		EntrypointGoArtifactRequest,
		EntrypointNpmArtifactRequest,
		EntrypointPypiArtifactRequest,
		EntrypointRubygemsArtifactRequest,
	}
	// EntrypointsScan lists all entrypoints related to the scan command.
	EntrypointsScan = []string{
		EntrypointScanReport,
		EntrypointScanVulnerability,
	}
	// EntrypointsDiff lists all entrypoints related to the diff command.
	EntrypointsDiff = []string{
		EntrypointDiffReport,
		EntrypointDiffDependencyChange,
		EntrypointDiffVulnerability,
	}
	// EntrypointsSBOM lists all entrypoints related to the sbom command.
	EntrypointsSBOM = []string{
		EntrypointSBOMReport,
		EntrypointSBOMComponent,
	}
	// EntrypointsFix lists all entrypoints related to the fix command.
	EntrypointsFix = []string{
		EntrypointFixPlan,
		EntrypointFixPlanStep,
	}
	// EntrypointsTriage lists all entrypoints related to the triage command.
	EntrypointsTriage = []string{
		EntrypointTriageReport,
		EntrypointTriageCluster,
	}

	// AllEntrypoints contains every canonical entrypoint defined in Deputy.
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
