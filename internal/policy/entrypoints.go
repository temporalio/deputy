package policy

import "slices"

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
	// EntrypointOCIArtifactRequest triggers when the proxy handles an OCI image request.
	EntrypointOCIArtifactRequest = "oci_artifact_request"

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

	// Container image diff entrypoints - for comparing two container images
	// EntrypointContainerDiffReport triggers after a container image diff completes.
	EntrypointContainerDiffReport = "container_diff_report"
	// EntrypointContainerDiffChange triggers for each package change between container images.
	EntrypointContainerDiffChange = "container_diff_change"
	// EntrypointContainerDiffVulnerability triggers for each vulnerability difference.
	EntrypointContainerDiffVulnerability = "container_diff_vulnerability"
	// EntrypointContainerDiffLayer triggers for each layer difference analysis.
	EntrypointContainerDiffLayer = "container_diff_layer"
	// EntrypointContainerDiffConfig triggers for configuration changes between images.
	EntrypointContainerDiffConfig = "container_diff_config"

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

	// Dockerfile entrypoints - for analyzing Dockerfiles
	// EntrypointDockerfileReport triggers after a Dockerfile is parsed.
	EntrypointDockerfileReport = "dockerfile_report"
	// EntrypointDockerfileStage triggers for each stage in a multi-stage Dockerfile.
	EntrypointDockerfileStage = "dockerfile_stage"
)

var (
	// EntrypointsProxy lists all entrypoints related to the artifact proxy.
	EntrypointsProxy = []string{
		EntrypointGoArtifactRequest,
		EntrypointNpmArtifactRequest,
		EntrypointPypiArtifactRequest,
		EntrypointRubygemsArtifactRequest,
		EntrypointOCIArtifactRequest,
	}
	// EntrypointsScan lists all entrypoints related to the scan command.
	EntrypointsScan = []string{
		EntrypointScanReport,
		EntrypointScanVulnerability,
	}
	// EntrypointsDiff lists all entrypoints related to the diff command (git repositories).
	EntrypointsDiff = []string{
		EntrypointDiffReport,
		EntrypointDiffDependencyChange,
		EntrypointDiffVulnerability,
	}
	// EntrypointsContainerDiff lists all entrypoints related to container image diff.
	EntrypointsContainerDiff = []string{
		EntrypointContainerDiffReport,
		EntrypointContainerDiffChange,
		EntrypointContainerDiffVulnerability,
		EntrypointContainerDiffLayer,
		EntrypointContainerDiffConfig,
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
	// EntrypointsDockerfile lists all entrypoints related to Dockerfile analysis.
	EntrypointsDockerfile = []string{
		EntrypointDockerfileReport,
		EntrypointDockerfileStage,
	}

	// AllEntrypoints contains every canonical entrypoint defined in Deputy.
	AllEntrypoints = slices.Concat(EntrypointsProxy, EntrypointsScan, EntrypointsDiff, EntrypointsContainerDiff, EntrypointsSBOM, EntrypointsFix, EntrypointsTriage, EntrypointsDockerfile)

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
