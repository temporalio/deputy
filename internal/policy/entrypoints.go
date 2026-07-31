package policy

import (
	"maps"
	"slices"
	"strings"
)

// Entrypoint represents a canonical policy evaluation entrypoint.
// Using a distinct type provides compile-time safety and makes entrypoint
// usage explicit throughout the codebase.
type Entrypoint string

// String returns the entrypoint name.
func (e Entrypoint) String() string { return string(e) }

// IsValid reports whether this is a known canonical entrypoint.
func (e Entrypoint) IsValid() bool {
	_, ok := allowedEntrypointsSet[string(e)]
	return ok
}

// Category returns which command category this entrypoint belongs to.
func (e Entrypoint) Category() string {
	switch e {
	case EntrypointGoArtifactRequest, EntrypointNpmArtifactRequest,
		EntrypointPypiArtifactRequest, EntrypointRubygemsArtifactRequest,
		EntrypointOCIArtifactRequest:
		return "proxy"
	case EntrypointScanReport, EntrypointScanVulnerability:
		return "scan"
	case EntrypointDiffReport, EntrypointDiffDependencyChange, EntrypointDiffVulnerability:
		return "diff"
	case EntrypointContainerDiffReport, EntrypointContainerDiffChange,
		EntrypointContainerDiffVulnerability, EntrypointContainerDiffLayer,
		EntrypointContainerDiffConfig:
		return "container_diff"
	case EntrypointSBOMReport, EntrypointSBOMComponent:
		return "sbom"
	case EntrypointFixPlan, EntrypointFixPlanStep:
		return "fix"
	case EntrypointTriageReport, EntrypointTriageCluster:
		return "triage"
	case EntrypointDockerfileReport, EntrypointDockerfileStage:
		return "dockerfile"
	case EntrypointSecretsReport, EntrypointSecretsFinding:
		return "secrets"
	case EntrypointGraphReport, EntrypointGraphNode, EntrypointGraphEdge:
		return "graph"
	case EntrypointServiceScanRequest, EntrypointServiceListRequest,
		EntrypointServiceSBOMRequest, EntrypointServiceDiffRequest,
		EntrypointServiceSecretsRequest, EntrypointServiceGraphRequest:
		return "server"
	case EntrypointSandboxExecution, EntrypointSandboxCommand, EntrypointSandboxNetwork:
		return "sandbox"
	default:
		return ""
	}
}

// categoryAliases maps legacy category inputs, kept for CLI/API/MCP
// compatibility, to their canonical category. It is the single source of truth
// for both NormalizeCategory and CategoryAliases.
var categoryAliases = map[string]string{
	"container": "container_diff",
	"service":   "server",
	"exec":      "sandbox",
}

// NormalizeCategory returns Deputy's canonical policy category for category,
// resolving legacy aliases such as "container" -> "container_diff",
// "service" -> "server", and "exec" -> "sandbox".
func NormalizeCategory(category string) string {
	c := strings.ToLower(strings.TrimSpace(category))
	if canonical, ok := categoryAliases[c]; ok {
		return canonical
	}
	return c
}

// Categories returns the sorted set of canonical policy categories, derived
// from the registered entrypoints so callers (CLI/API/MCP) never hand-maintain
// a parallel list.
func Categories() []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, len(AllEntrypoints))
	for _, ep := range AllEntrypoints {
		c := ep.Category()
		if c == "" {
			continue
		}
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	slices.Sort(out)
	return out
}

// CategoryAliases returns a copy of the legacy category aliases mapped to their
// canonical category, so surfaces can advertise the accepted inputs.
func CategoryAliases() map[string]string {
	return maps.Clone(categoryAliases)
}

// Canonical entrypoint constants. Use these typed values instead of raw strings.
const (
	// EntrypointGoArtifactRequest triggers when the proxy handles a Go module request.
	EntrypointGoArtifactRequest Entrypoint = "go_artifact_request"
	// EntrypointNpmArtifactRequest triggers when the proxy handles an NPM package request.
	EntrypointNpmArtifactRequest Entrypoint = "npm_artifact_request"
	// EntrypointPypiArtifactRequest triggers when the proxy handles a PyPI package request.
	EntrypointPypiArtifactRequest Entrypoint = "pypi_artifact_request"
	// EntrypointRubygemsArtifactRequest triggers when the proxy handles a RubyGems package request.
	EntrypointRubygemsArtifactRequest Entrypoint = "rubygems_artifact_request"
	// EntrypointOCIArtifactRequest triggers when the proxy handles an OCI image request.
	EntrypointOCIArtifactRequest Entrypoint = "oci_artifact_request"

	// EntrypointScanReport triggers after a scan completes, providing the full report.
	EntrypointScanReport Entrypoint = "scan_report"
	// EntrypointScanVulnerability triggers for each vulnerability found during a scan.
	EntrypointScanVulnerability Entrypoint = "scan_vulnerability"

	// EntrypointDiffReport triggers after a diff completes, providing the full report.
	EntrypointDiffReport Entrypoint = "diff_report"
	// EntrypointDiffDependencyChange triggers for each dependency change found during a diff.
	EntrypointDiffDependencyChange Entrypoint = "diff_dependency_change"
	// EntrypointDiffVulnerability triggers for each vulnerability found during a diff.
	EntrypointDiffVulnerability Entrypoint = "diff_vulnerability"

	// Container image diff entrypoints - for comparing two container images
	// EntrypointContainerDiffReport triggers after a container image diff completes.
	EntrypointContainerDiffReport Entrypoint = "container_diff_report"
	// EntrypointContainerDiffChange triggers for each package change between container images.
	EntrypointContainerDiffChange Entrypoint = "container_diff_change"
	// EntrypointContainerDiffVulnerability triggers for each vulnerability difference.
	EntrypointContainerDiffVulnerability Entrypoint = "container_diff_vulnerability"
	// EntrypointContainerDiffLayer triggers for each layer difference analysis.
	EntrypointContainerDiffLayer Entrypoint = "container_diff_layer"
	// EntrypointContainerDiffConfig triggers for configuration changes between images.
	EntrypointContainerDiffConfig Entrypoint = "container_diff_config"

	// EntrypointSBOMReport triggers after an SBOM is generated.
	EntrypointSBOMReport Entrypoint = "sbom_report"
	// EntrypointSBOMComponent triggers for each component in an SBOM.
	EntrypointSBOMComponent Entrypoint = "sbom_component"

	// EntrypointFixPlan triggers after a remediation plan is generated.
	EntrypointFixPlan Entrypoint = "fix_plan"
	// EntrypointFixPlanStep triggers for each step in a remediation plan.
	EntrypointFixPlanStep Entrypoint = "fix_plan_step"

	// EntrypointTriageReport triggers after a triage report is generated.
	EntrypointTriageReport Entrypoint = "triage_report"
	// EntrypointTriageCluster triggers for each cluster of issues in a triage report.
	EntrypointTriageCluster Entrypoint = "triage_cluster"

	// Dockerfile entrypoints - for analyzing Dockerfiles
	// EntrypointDockerfileReport triggers after a Dockerfile is parsed.
	EntrypointDockerfileReport Entrypoint = "dockerfile_report"
	// EntrypointDockerfileStage triggers for each stage in a multi-stage Dockerfile.
	EntrypointDockerfileStage Entrypoint = "dockerfile_stage"

	// Secrets entrypoints - for secret detection policies
	// EntrypointSecretsReport triggers after a secrets scan completes.
	EntrypointSecretsReport Entrypoint = "secrets_report"
	// EntrypointSecretsFinding triggers for each secret found during a scan.
	EntrypointSecretsFinding Entrypoint = "secrets_finding"

	// Graph entrypoints - for dependency graph analysis and policies
	// EntrypointGraphReport triggers after a graph is built, providing the full graph.
	EntrypointGraphReport Entrypoint = "graph_report"
	// EntrypointGraphNode triggers for each node in the dependency graph.
	// Available variables: node (with purl, name, version, ecosystem, direct, depth, etc.)
	EntrypointGraphNode Entrypoint = "graph_node"
	// EntrypointGraphEdge triggers for each edge in the dependency graph.
	// Available variables: edge (with from, to PURLs), from_node, to_node
	EntrypointGraphEdge Entrypoint = "graph_edge"

	// Service entrypoints - for API request authorization when Deputy runs as a server.
	// These enable RBAC/ABAC policies based on JWT claims (jwt.*) for multi-tenant deployments.

	// EntrypointServiceScanRequest triggers before a scan is executed via the API.
	// Use this to authorize which targets a user/service can scan.
	EntrypointServiceScanRequest Entrypoint = "service_scan_request"
	// EntrypointServiceListRequest triggers before a list operation via the API.
	EntrypointServiceListRequest Entrypoint = "service_list_request"
	// EntrypointServiceSBOMRequest triggers before SBOM generation via the API.
	EntrypointServiceSBOMRequest Entrypoint = "service_sbom_request"
	// EntrypointServiceDiffRequest triggers before a diff operation via the API.
	EntrypointServiceDiffRequest Entrypoint = "service_diff_request"
	// EntrypointServiceSecretsRequest triggers before a secrets scan via the API.
	EntrypointServiceSecretsRequest Entrypoint = "service_secrets_request"
	// EntrypointServiceGraphRequest triggers before a graph operation via the API.
	EntrypointServiceGraphRequest Entrypoint = "service_graph_request"

	// Sandbox entrypoints - for controlling sandboxed execution.
	// These enable policies to control what can run in sandboxes, with what configuration,
	// and what network/filesystem access is allowed.

	// EntrypointSandboxExecution triggers before any sandbox execution begins.
	// Use this to authorize sandbox executions based on source, command, and config.
	// Available variables: command, workspace_dir, requested_config, context
	EntrypointSandboxExecution Entrypoint = "sandbox_execution"
	// EntrypointSandboxCommand triggers for each command executed within a sandbox session.
	// Use this for fine-grained command-level control within ongoing sandboxes.
	// Available variables: command, sandbox_config, context
	EntrypointSandboxCommand Entrypoint = "sandbox_command"
	// EntrypointSandboxNetwork triggers when a sandbox requests network access.
	// Use this to implement network allowlists or block specific destinations.
	// Available variables: host, port, protocol, sandbox_config, context
	EntrypointSandboxNetwork Entrypoint = "sandbox_network"
)

var (
	// EntrypointsProxy lists all entrypoints related to the artifact proxy.
	EntrypointsProxy = []Entrypoint{
		EntrypointGoArtifactRequest,
		EntrypointNpmArtifactRequest,
		EntrypointPypiArtifactRequest,
		EntrypointRubygemsArtifactRequest,
		EntrypointOCIArtifactRequest,
	}
	// EntrypointsScan lists all entrypoints related to the scan command.
	EntrypointsScan = []Entrypoint{
		EntrypointScanReport,
		EntrypointScanVulnerability,
	}
	// EntrypointsDiff lists all entrypoints related to the diff command (git repositories).
	EntrypointsDiff = []Entrypoint{
		EntrypointDiffReport,
		EntrypointDiffDependencyChange,
		EntrypointDiffVulnerability,
	}
	// EntrypointsContainerDiff lists all entrypoints related to container image diff.
	EntrypointsContainerDiff = []Entrypoint{
		EntrypointContainerDiffReport,
		EntrypointContainerDiffChange,
		EntrypointContainerDiffVulnerability,
		EntrypointContainerDiffLayer,
		EntrypointContainerDiffConfig,
	}
	// EntrypointsSBOM lists all entrypoints related to the sbom command.
	EntrypointsSBOM = []Entrypoint{
		EntrypointSBOMReport,
		EntrypointSBOMComponent,
	}
	// EntrypointsFix lists all entrypoints related to the fix command.
	EntrypointsFix = []Entrypoint{
		EntrypointFixPlan,
		EntrypointFixPlanStep,
	}
	// EntrypointsTriage lists all entrypoints related to the triage command.
	EntrypointsTriage = []Entrypoint{
		EntrypointTriageReport,
		EntrypointTriageCluster,
	}
	// EntrypointsDockerfile lists all entrypoints related to Dockerfile analysis.
	EntrypointsDockerfile = []Entrypoint{
		EntrypointDockerfileReport,
		EntrypointDockerfileStage,
	}
	// EntrypointsSecrets lists all entrypoints related to secret detection.
	EntrypointsSecrets = []Entrypoint{
		EntrypointSecretsReport,
		EntrypointSecretsFinding,
	}
	// EntrypointsGraph lists all entrypoints related to dependency graph analysis.
	EntrypointsGraph = []Entrypoint{
		EntrypointGraphReport,
		EntrypointGraphNode,
		EntrypointGraphEdge,
	}
	// EntrypointsService lists all entrypoints related to API request authorization.
	// These enable RBAC/ABAC when Deputy runs as a shared service (server mode).
	EntrypointsService = []Entrypoint{
		EntrypointServiceScanRequest,
		EntrypointServiceListRequest,
		EntrypointServiceSBOMRequest,
		EntrypointServiceDiffRequest,
		EntrypointServiceSecretsRequest,
		EntrypointServiceGraphRequest,
	}
	// EntrypointsSandbox lists all entrypoints related to sandbox execution control.
	// These enable policies to control what runs in sandboxes and with what permissions.
	EntrypointsSandbox = []Entrypoint{
		EntrypointSandboxExecution,
		EntrypointSandboxCommand,
		EntrypointSandboxNetwork,
	}

	// AllEntrypoints contains every canonical entrypoint defined in Deputy.
	AllEntrypoints = slices.Concat(EntrypointsProxy, EntrypointsScan, EntrypointsDiff, EntrypointsContainerDiff, EntrypointsSBOM, EntrypointsFix, EntrypointsTriage, EntrypointsDockerfile, EntrypointsSecrets, EntrypointsGraph, EntrypointsService, EntrypointsSandbox)

	allowedEntrypointsSet = buildEntrypointSet(AllEntrypoints)
	allowedCommands       = []string{"proxy", "scan", "diff", "sbom", "fix", "triage", "secrets", "graph", "server", "sandbox"}
	allowedCommandsSet    = buildSet(allowedCommands)
)

func buildSet(items []string) map[string]struct{} {
	m := make(map[string]struct{}, len(items))
	for _, v := range items {
		m[v] = struct{}{}
	}
	return m
}

func buildEntrypointSet(items []Entrypoint) map[string]struct{} {
	m := make(map[string]struct{}, len(items))
	for _, v := range items {
		m[string(v)] = struct{}{}
	}
	return m
}

// IsAllowedEntrypoint reports whether the name matches a canonical entrypoint.
func IsAllowedEntrypoint(name string) bool {
	_, ok := allowedEntrypointsSet[name]
	return ok
}

// NormalizeCommand returns Deputy's canonical policy command for command.
// It accepts legacy aliases kept for policy bundle compatibility, such as
// "exec" for the sandbox execution command.
func NormalizeCommand(command string) string {
	switch strings.ToLower(strings.TrimSpace(command)) {
	case "exec":
		return "sandbox"
	default:
		return strings.ToLower(strings.TrimSpace(command))
	}
}

// IsAllowedCommand reports whether the command is one of the known policy commands.
func IsAllowedCommand(cmd string) bool {
	_, ok := allowedCommandsSet[NormalizeCommand(cmd)]
	return ok
}

// CanonicalCommands returns the canonical policy command names.
func CanonicalCommands() []string {
	return slices.Clone(allowedCommands)
}
