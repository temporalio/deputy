// Package policy provides CEL-based policy evaluation for Deputy.
//
// This file provides canonical example inputs for policy development and testing.
// Examples use real Deputy proto types with realistic values.

package policy

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	containerv1 "github.com/picatz/deputy/gen/deputy/container/v1"
	dependencyv1 "github.com/picatz/deputy/gen/deputy/dependency/v1"
	policyv1 "github.com/picatz/deputy/gen/deputy/policy/v1"
	vulnerabilityv1 "github.com/picatz/deputy/gen/deputy/vulnerability/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ExampleLevel describes how much detail to include in generated examples.
type ExampleLevel string

const (
	// ExampleLevelMinimal includes only required fields with simplest values.
	ExampleLevelMinimal ExampleLevel = "minimal"
	// ExampleLevelTypical includes common fields users will encounter.
	ExampleLevelTypical ExampleLevel = "typical"
	// ExampleLevelComprehensive includes all fields with rich examples.
	ExampleLevelComprehensive ExampleLevel = "comprehensive"
)

// ExampleCategory groups related entrypoints for discovery.
type ExampleCategory struct {
	Name        string
	Description string
	Entrypoints []Entrypoint
}

// ExampleCategories organizes entrypoints into logical groups.
var ExampleCategories = []ExampleCategory{
	{
		Name:        "scan",
		Description: "Vulnerability scanning policies",
		Entrypoints: []Entrypoint{
			EntrypointScanVulnerability,
			EntrypointScanReport,
		},
	},
	{
		Name:        "proxy",
		Description: "Package proxy request policies",
		Entrypoints: []Entrypoint{
			EntrypointGoArtifactRequest,
			EntrypointNpmArtifactRequest,
			EntrypointPypiArtifactRequest,
			EntrypointRubygemsArtifactRequest,
			EntrypointOCIArtifactRequest,
		},
	},
	{
		Name:        "diff",
		Description: "Dependency diff policies",
		Entrypoints: []Entrypoint{
			EntrypointDiffReport,
			EntrypointDiffVulnerability,
			EntrypointDiffDependencyChange,
		},
	},
	{
		Name:        "container",
		Description: "Container image policies",
		Entrypoints: []Entrypoint{
			EntrypointContainerDiffReport,
			EntrypointContainerDiffChange,
			EntrypointContainerDiffVulnerability,
		},
	},
	{
		Name:        "dockerfile",
		Description: "Dockerfile analysis policies",
		Entrypoints: []Entrypoint{
			EntrypointDockerfileReport,
			EntrypointDockerfileStage,
		},
	},
	{
		Name:        "sbom",
		Description: "SBOM generation policies",
		Entrypoints: []Entrypoint{
			EntrypointSBOMReport,
			EntrypointSBOMComponent,
		},
	},
	{
		Name:        "graph",
		Description: "Dependency graph policies",
		Entrypoints: []Entrypoint{
			EntrypointGraphReport,
			EntrypointGraphNode,
			EntrypointGraphEdge,
		},
	},
	{
		Name:        "secrets",
		Description: "Secret scanning policies",
		Entrypoints: []Entrypoint{
			EntrypointSecretsReport,
			EntrypointSecretsFinding,
		},
	},
	{
		Name:        "service",
		Description: "API authorization policies",
		Entrypoints: []Entrypoint{
			EntrypointServiceScanRequest,
			EntrypointServiceListRequest,
			EntrypointServiceSBOMRequest,
		},
	},
}

// ExampleInput contains a generated example for policy testing.
type ExampleInput struct {
	Entrypoint  Entrypoint
	Level       ExampleLevel
	Description string
	Input       map[string]any
	JSON        string // Pretty-printed JSON
	Comments    []string
}

// GenerateExample creates a canonical example input for the given entrypoint.
func GenerateExample(ep Entrypoint, level ExampleLevel) (*ExampleInput, error) {
	profile := GetBindingProfile(ep)
	if profile == nil {
		return nil, fmt.Errorf("unknown entrypoint: %s", ep)
	}

	input := make(map[string]any)
	comments := []string{}

	// Generate values for required variables
	for _, varName := range profile.Required {
		value, comment := generateVariableValue(ep, varName, level, true)
		input[varName] = value
		if comment != "" {
			comments = append(comments, fmt.Sprintf("%s: %s", varName, comment))
		}
	}

	// For comprehensive level, include optional variables
	if level == ExampleLevelComprehensive {
		for _, varName := range profile.Optional {
			value, comment := generateVariableValue(ep, varName, level, false)
			input[varName] = value
			if comment != "" {
				comments = append(comments, fmt.Sprintf("%s (optional): %s", varName, comment))
			}
		}
	}

	// Convert to pretty JSON
	jsonBytes, err := json.MarshalIndent(input, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshaling example: %w", err)
	}

	return &ExampleInput{
		Entrypoint:  ep,
		Level:       level,
		Description: profile.Description,
		Input:       input,
		JSON:        string(jsonBytes),
		Comments:    comments,
	}, nil
}

// generateVariableValue creates a realistic value for a variable at an entrypoint.
func generateVariableValue(ep Entrypoint, varName string, level ExampleLevel, required bool) (any, string) {
	switch varName {
	case "env":
		return generateEnv(ep), "execution environment context"
	case "vulnerability":
		return generateVulnerability(level), "the vulnerability being evaluated"
	case "vulnerabilities":
		return generateVulnerabilities(level), "list of all vulnerabilities"
	case "pkg":
		return generatePackage(level, false), "the affected package"
	case "packages":
		return generatePackages(level), "list of all scanned packages"
	case "request":
		return generateProxyRequest(ep, level), "the package request details"
	case "jwt":
		return generateJWT(level), "JWT claims (anonymous if no auth)"
	case "target":
		return generateTarget(level), "scan target metadata"
	case "image", "image_info":
		return generateImageInfo(level), "container image configuration"
	case "licenses":
		return []string{"MIT", "Apache-2.0"}, "SPDX license identifiers"
	case "changes":
		return generateDiffChanges(level), "dependency changes"
	case "change":
		return generateDiffChange(level), "single dependency change"
	case "dependency":
		return generatePackage(level, true), "dependency being changed"
	case "node":
		return generateGraphNode(level), "dependency graph node"
	case "nodes":
		return generateGraphNodes(level), "all graph nodes"
	case "edges":
		return generateGraphEdges(level), "all graph edges"
	case "edge":
		return generateGraphEdge(level), "single graph edge"
	case "from_node":
		return generateGraphNode(level), "source node of edge"
	case "to_node":
		return generateGraphNode(level), "target node of edge"
	case "roots":
		return generateGraphNodes(level)[:1], "direct dependency nodes"
	case "stats":
		return generateGraphStats(level), "graph statistics"
	case "dockerfile":
		return generateDockerfile(level), "parsed Dockerfile"
	case "dockerfile_analysis":
		return generateDockerfileAnalysis(level), "Dockerfile analysis results"
	case "stage":
		return generateDockerfileStage(level), "single Dockerfile stage"
	case "sbom":
		return generateSBOM(level), "SBOM document"
	case "component":
		return generatePackage(level, false), "SBOM component"
	case "secrets", "report":
		return generateSecretsReport(level), "secrets scan results"
	case "secret":
		return generateSecretFinding(level), "single secret finding"
	case "base_image":
		return generateImageRef("nginx", "1.24"), "base image reference"
	case "target_image":
		return generateImageRef("nginx", "1.25"), "target image reference"
	case "package_changes":
		return generatePackageChanges(level), "package changes between images"
	case "vulnerability_changes":
		return generateVulnerabilityChanges(level), "vulnerability changes"
	case "config_changes":
		return generateConfigChanges(level), "image config changes"
	case "layer_analysis":
		return generateLayerAnalysis(level), "layer-by-layer analysis"
	case "summary":
		return generateDiffSummary(level), "diff summary"
	case "plan":
		return generateFixPlan(level), "remediation plan"
	case "step":
		return generateFixStep(level), "single remediation step"
	case "findings":
		return generateTriageFindings(level), "triage findings"
	case "cluster":
		return generateTriageCluster(level), "triage cluster"
	case "graph":
		return generateGraph(level), "full dependency graph"
	case "ancestors":
		return generateGraphNodes(level), "ancestor nodes"
	case "descendants":
		return generateGraphNodes(level), "descendant nodes"
	case "layer":
		return generateLayerDiff(level), "layer difference"
	case "repo":
		return "github.com/example/app", "repository path"
	default:
		return nil, ""
	}
}

// generateEnv creates an Environment proto as a map.
func generateEnv(ep Entrypoint) map[string]any {
	// Determine command from entrypoint
	command := "scan"
	switch {
	case strings.HasPrefix(string(ep), "go_") ||
		strings.HasPrefix(string(ep), "npm_") ||
		strings.HasPrefix(string(ep), "pypi_") ||
		strings.HasPrefix(string(ep), "rubygems_") ||
		strings.HasPrefix(string(ep), "oci_"):
		command = "proxy"
	case strings.HasPrefix(string(ep), "diff_") ||
		strings.HasPrefix(string(ep), "container_diff_"):
		command = "diff"
	case strings.HasPrefix(string(ep), "sbom_"):
		command = "sbom"
	case strings.HasPrefix(string(ep), "graph_"):
		command = "graph"
	case strings.HasPrefix(string(ep), "dockerfile_"):
		command = "scan"
	case strings.HasPrefix(string(ep), "secrets_"):
		command = "secrets"
	case strings.HasPrefix(string(ep), "service_"):
		command = "server"
	case strings.HasPrefix(string(ep), "fix_"):
		command = "fix"
	case strings.HasPrefix(string(ep), "triage_"):
		command = "triage"
	}

	return map[string]any{
		"command":    command,
		"entrypoint": string(ep),
	}
}

// generateVulnerability creates a realistic vulnerability finding.
func generateVulnerability(level ExampleLevel) map[string]any {
	finding := &vulnerabilityv1.Finding{
		AdvisoryId: "CVE-2024-1234",
		Package: &dependencyv1.Package{
			Name:      "example-pkg",
			Version:   "1.2.3",
			Ecosystem: "npm",
			Direct:    true,
			Purl:      "pkg:npm/example-pkg@1.2.3",
		},
		Affected: true,
		Advisory: &vulnerabilityv1.Advisory{
			Id:      "CVE-2024-1234",
			Summary: "Remote code execution vulnerability in example-pkg",
			Severity: &vulnerabilityv1.Severity{
				Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_CRITICAL,
				Type:  vulnerabilityv1.SeverityType_SEVERITY_TYPE_CVSS_V3,
				Score: 9.8,
			},
			FixedVersions: []string{"1.2.4", "1.3.0"},
			Cwes:          []string{"CWE-94"},
			Published:     timestamppb.New(time.Date(2024, 1, 15, 0, 0, 0, 0, time.UTC)),
		},
	}

	if level == ExampleLevelComprehensive {
		finding.Advisory.Aliases = []string{"GHSA-xxxx-yyyy-zzzz"}
		finding.Advisory.Details = "A remote code execution vulnerability exists in example-pkg versions prior to 1.2.4. An attacker can exploit this by sending a specially crafted payload."
		finding.Advisory.References = []string{
			"https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
			"https://github.com/example/example-pkg/security/advisories/GHSA-xxxx-yyyy-zzzz",
		}
		// Add enrichment fields
		epss := 0.85
		epssPercentile := 0.97
		inKev := true
		finding.Epss = &epss
		finding.EpssPercentile = &epssPercentile
		finding.InKev = &inKev
		finding.KevDateAdded = proto.String("2024-01-20")
		finding.KevDueDate = proto.String("2024-02-10")
		finding.KevRequiredAction = proto.String("Apply updates per vendor instructions")
		// Add graph fields
		finding.Path = []string{"my-app", "dependency-a", "example-pkg"}
		depth := int32(2)
		finding.Depth = &depth
		// Add layer details for container scans
		finding.Package.LayerDetails = &containerv1.LayerDetails{
			Index:       2,
			DiffId:      "sha256:abc123...",
			Command:     "RUN npm install",
			InBaseImage: false,
		}
	}

	return mustProtoToMap(finding)
}

// generateVulnerabilities creates a list of vulnerabilities.
func generateVulnerabilities(level ExampleLevel) []map[string]any {
	vulns := []map[string]any{generateVulnerability(level)}

	if level != ExampleLevelMinimal {
		// Add a second vulnerability with different characteristics
		finding := &vulnerabilityv1.Finding{
			AdvisoryId: "CVE-2024-5678",
			Package: &dependencyv1.Package{
				Name:      "transitive-pkg",
				Version:   "2.0.0",
				Ecosystem: "npm",
				Direct:    false,
				Purl:      "pkg:npm/transitive-pkg@2.0.0",
			},
			Affected: true,
			Advisory: &vulnerabilityv1.Advisory{
				Id:      "CVE-2024-5678",
				Summary: "Denial of service in transitive-pkg",
				Severity: &vulnerabilityv1.Severity{
					Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_MEDIUM,
					Type:  vulnerabilityv1.SeverityType_SEVERITY_TYPE_CVSS_V3,
					Score: 5.3,
				},
				// No fix available
				Cwes: []string{"CWE-400"},
			},
		}
		vulns = append(vulns, mustProtoToMap(finding))
	}

	return vulns
}

// generatePackage creates a package/dependency.
func generatePackage(level ExampleLevel, direct bool) map[string]any {
	pkg := &dependencyv1.Package{
		Name:      "example-pkg",
		Version:   "1.2.3",
		Ecosystem: "npm",
		Direct:    direct,
		Purl:      "pkg:npm/example-pkg@1.2.3",
		Licenses:  []string{"MIT"},
	}

	if level == ExampleLevelComprehensive {
		pkg.Locations = []string{"package-lock.json"}
		pkg.ManifestRefs = []*dependencyv1.ManifestRef{
			{
				Path:    "package.json",
				Manager: "npm",
				Groups:  []string{"dependencies"},
			},
		}
	}

	return mustProtoToMap(pkg)
}

// generatePackages creates a list of packages.
func generatePackages(level ExampleLevel) []map[string]any {
	pkgs := []map[string]any{generatePackage(level, true)}

	if level != ExampleLevelMinimal {
		indirect := &dependencyv1.Package{
			Name:      "transitive-pkg",
			Version:   "2.0.0",
			Ecosystem: "npm",
			Direct:    false,
			Purl:      "pkg:npm/transitive-pkg@2.0.0",
			Licenses:  []string{"Apache-2.0"},
		}
		pkgs = append(pkgs, mustProtoToMap(indirect))
	}

	return pkgs
}

// generateProxyRequest creates a proxy request based on ecosystem.
func generateProxyRequest(ep Entrypoint, level ExampleLevel) map[string]any {
	req := &policyv1.ProxyRequest{
		Version:   "1.2.3",
		Operation: "download",
	}

	switch ep {
	case EntrypointGoArtifactRequest:
		req.Module = "github.com/example/module"
		req.Package = "github.com/example/module"
		req.Ecosystem = "go"
	case EntrypointNpmArtifactRequest:
		req.Package = "lodash"
		req.Ecosystem = "npm"
	case EntrypointPypiArtifactRequest:
		req.Package = "requests"
		req.Ecosystem = "pypi"
	case EntrypointRubygemsArtifactRequest:
		req.Package = "rails"
		req.Ecosystem = "rubygems"
	case EntrypointOCIArtifactRequest:
		req.Package = "ghcr.io/example/app"
		req.Ecosystem = "oci"
		req.Version = "v1.0.0"
	default:
		req.Package = "example-pkg"
		req.Ecosystem = "npm"
	}

	return mustProtoToMap(req)
}

// generateJWT creates JWT claims.
func generateJWT(level ExampleLevel) map[string]any {
	if level == ExampleLevelMinimal {
		return map[string]any{
			"anonymous": true,
		}
	}

	jwt := &policyv1.JWTClaims{
		Anonymous: false,
		Sub:       "user:alice@example.com",
		Iss:       "https://auth.example.com",
		Aud:       []string{"deputy-proxy"},
		Exp:       time.Now().Add(time.Hour).Unix(),
		Iat:       time.Now().Unix(),
	}

	if level == ExampleLevelComprehensive {
		jwt.CustomClaims = map[string]string{
			"roles":  "developer,scanner",
			"teams":  "platform,security",
			"tenant": "acme-corp",
		}
	}

	return mustProtoToMap(jwt)
}

// generateTarget creates target metadata.
func generateTarget(level ExampleLevel) map[string]any {
	target := map[string]any{
		"display_path": "/path/to/project",
		"type":         "directory",
	}

	if level != ExampleLevelMinimal {
		target["commit_hash"] = "abc123def456"
		target["reference"] = "main"
		target["origin"] = "https://github.com/example/project.git"
	}

	return target
}

// generateImageInfo creates container image information.
func generateImageInfo(level ExampleLevel) map[string]any {
	info := map[string]any{
		"registry":   "ghcr.io",
		"repository": "example/app",
		"tag":        "v1.0.0",
	}

	if level != ExampleLevelMinimal {
		info["digest"] = "sha256:abc123..."
		info["config"] = map[string]any{
			"user":          "nobody",
			"is_root":       false,
			"env":           []string{"NODE_ENV=production"},
			"exposed_ports": []string{"8080/tcp"},
			"working_dir":   "/app",
		}
		info["metadata"] = map[string]any{
			"architecture": "amd64",
			"os":           "linux",
			"layer_count":  12,
			"size":         52428800,
		}
	}

	return info
}

// generateDiffChanges creates dependency diff changes.
func generateDiffChanges(level ExampleLevel) []map[string]any {
	changes := []map[string]any{
		{
			"type":        "upgraded",
			"name":        "example-pkg",
			"ecosystem":   "npm",
			"old_version": "1.2.3",
			"new_version": "1.3.0",
		},
	}

	if level != ExampleLevelMinimal {
		changes = append(changes, map[string]any{
			"type":        "added",
			"name":        "new-pkg",
			"ecosystem":   "npm",
			"new_version": "1.0.0",
		})
	}

	return changes
}

// generateDiffChange creates a single dependency change.
func generateDiffChange(level ExampleLevel) map[string]any {
	return map[string]any{
		"type":        "upgraded",
		"old_version": "1.2.3",
		"new_version": "1.3.0",
	}
}

// generateGraphNode creates a dependency graph node.
func generateGraphNode(level ExampleLevel) map[string]any {
	node := map[string]any{
		"name":      "example-pkg",
		"version":   "1.2.3",
		"ecosystem": "npm",
		"purl":      "pkg:npm/example-pkg@1.2.3",
		"direct":    true,
		"depth":     0,
	}

	if level == ExampleLevelComprehensive {
		node["vulnerabilities"] = generateVulnerabilities(ExampleLevelMinimal)
		node["licenses"] = []string{"MIT"}
	}

	return node
}

// generateGraphNodes creates multiple graph nodes.
func generateGraphNodes(level ExampleLevel) []map[string]any {
	nodes := []map[string]any{generateGraphNode(level)}

	if level != ExampleLevelMinimal {
		nodes = append(nodes, map[string]any{
			"name":      "transitive-pkg",
			"version":   "2.0.0",
			"ecosystem": "npm",
			"purl":      "pkg:npm/transitive-pkg@2.0.0",
			"direct":    false,
			"depth":     1,
		})
	}

	return nodes
}

// generateGraphEdge creates a dependency graph edge.
func generateGraphEdge(level ExampleLevel) map[string]any {
	edge := map[string]any{
		"from": "pkg:npm/example-pkg@1.2.3",
		"to":   "pkg:npm/transitive-pkg@2.0.0",
	}

	if level != ExampleLevelMinimal {
		edge["scope"] = "runtime"
	}

	return edge
}

// generateGraphEdges creates multiple graph edges.
func generateGraphEdges(level ExampleLevel) []map[string]any {
	return []map[string]any{generateGraphEdge(level)}
}

// generateGraphStats creates dependency graph statistics.
func generateGraphStats(level ExampleLevel) map[string]any {
	stats := map[string]any{
		"total_nodes":      42,
		"direct_nodes":     5,
		"transitive_nodes": 37,
		"max_depth":        4,
	}

	if level != ExampleLevelMinimal {
		stats["vulnerable_nodes"] = 2
		stats["ecosystems"] = map[string]int{
			"npm": 40,
			"go":  2,
		}
	}

	return stats
}

// generateDockerfile creates parsed Dockerfile data.
func generateDockerfile(level ExampleLevel) map[string]any {
	df := map[string]any{
		"path": "Dockerfile",
		"stages": []map[string]any{
			generateDockerfileStage(level),
		},
	}

	if level != ExampleLevelMinimal {
		df["args"] = map[string]string{"NODE_VERSION": "20"}
		df["final_stage"] = generateDockerfileStage(level)
	}

	return df
}

// generateDockerfileStage creates a single Dockerfile stage.
func generateDockerfileStage(level ExampleLevel) map[string]any {
	stage := map[string]any{
		"index":      0,
		"base_image": "node:20-alpine",
		"base_image_resolved": map[string]any{
			"registry":   "index.docker.io",
			"repository": "library/node",
			"tag":        "20-alpine",
		},
		"is_root": false,
		"user":    "node",
	}

	if level != ExampleLevelMinimal {
		stage["name"] = "builder"
		stage["workdir"] = "/app"
		stage["env_vars"] = map[string]string{"NODE_ENV": "production"}
		stage["exposed_ports"] = []string{"3000"}
	}

	if level == ExampleLevelComprehensive {
		stage["is_builder_stage"] = true
		stage["is_scratch"] = false
		stage["sensitive_env"] = []string{}
		stage["labels"] = map[string]string{
			"org.opencontainers.image.source": "https://github.com/example/app",
		}
		stage["healthcheck"] = map[string]any{
			"test":     []string{"CMD", "curl", "-f", "http://localhost:3000/health"},
			"interval": "30s",
			"timeout":  "10s",
			"retries":  3,
		}
	}

	return stage
}

// generateDockerfileAnalysis creates Dockerfile analysis results.
func generateDockerfileAnalysis(level ExampleLevel) map[string]any {
	analysis := map[string]any{
		"stage_count":           1,
		"has_multi_stage":       false,
		"final_stage_is_root":   false,
		"final_stage_is_scratch": false,
	}

	if level != ExampleLevelMinimal {
		analysis["builder_stage_count"] = 0
		analysis["sensitive_env_vars"] = []string{}
		analysis["has_add_url"] = false
	}

	return analysis
}

// generateSBOM creates SBOM document data.
func generateSBOM(level ExampleLevel) map[string]any {
	sbom := map[string]any{
		"format":  "cyclonedx",
		"version": "1.5",
	}

	if level != ExampleLevelMinimal {
		sbom["component_count"] = 42
		sbom["serial_number"] = "urn:uuid:12345678-1234-1234-1234-123456789abc"
	}

	return sbom
}

// generateSecretsReport creates secrets scan results.
func generateSecretsReport(level ExampleLevel) map[string]any {
	report := map[string]any{
		"total":    1,
		"findings": []map[string]any{generateSecretFinding(level)},
	}

	return report
}

// generateSecretFinding creates a single secret finding.
func generateSecretFinding(level ExampleLevel) map[string]any {
	finding := map[string]any{
		"rule_id":    "github-token",
		"severity":   "high",
		"file":       "config/secrets.yaml",
		"line":       42,
		"match_type": "pattern",
	}

	if level != ExampleLevelMinimal {
		finding["entropy"] = 4.5
		finding["redacted"] = "ghp_xxxx...xxxx"
	}

	return finding
}

// generateImageRef creates an image reference.
func generateImageRef(name, tag string) map[string]any {
	return map[string]any{
		"registry":   "index.docker.io",
		"repository": "library/" + name,
		"tag":        tag,
	}
}

// generatePackageChanges creates package change data.
func generatePackageChanges(level ExampleLevel) []map[string]any {
	return []map[string]any{
		{
			"type":        "upgraded",
			"name":        "openssl",
			"old_version": "1.1.1t",
			"new_version": "3.0.12",
		},
	}
}

// generateVulnerabilityChanges creates vulnerability change data.
func generateVulnerabilityChanges(level ExampleLevel) map[string]any {
	return map[string]any{
		"added":   generateVulnerabilities(ExampleLevelMinimal),
		"removed": []map[string]any{},
		"fixed":   1,
	}
}

// generateConfigChanges creates config change data.
func generateConfigChanges(level ExampleLevel) map[string]any {
	return map[string]any{
		"user_changed":       true,
		"old_user":           "root",
		"new_user":           "nobody",
		"env_added":          []string{"APP_VERSION=2.0"},
		"ports_changed":      false,
		"healthcheck_added":  true,
	}
}

// generateLayerAnalysis creates layer analysis data.
func generateLayerAnalysis(level ExampleLevel) []map[string]any {
	return []map[string]any{
		{
			"index":        0,
			"diff_id":      "sha256:abc...",
			"size":         10485760,
			"command":      "ADD file:... /",
			"in_base_image": true,
		},
	}
}

// generateDiffSummary creates diff summary data.
func generateDiffSummary(level ExampleLevel) map[string]any {
	return map[string]any{
		"packages_added":   5,
		"packages_removed": 2,
		"packages_upgraded": 10,
		"vulns_introduced": 1,
		"vulns_resolved":   3,
	}
}

// generateFixPlan creates a remediation plan.
func generateFixPlan(level ExampleLevel) map[string]any {
	return map[string]any{
		"steps": []map[string]any{generateFixStep(level)},
		"total_fixes": 1,
	}
}

// generateFixStep creates a single remediation step.
func generateFixStep(level ExampleLevel) map[string]any {
	return map[string]any{
		"package":     "example-pkg",
		"ecosystem":   "npm",
		"from_version": "1.2.3",
		"to_version":  "1.2.4",
		"command":     "npm install example-pkg@1.2.4",
		"fixes":       []string{"CVE-2024-1234"},
	}
}

// generateTriageFindings creates triage findings.
func generateTriageFindings(level ExampleLevel) []map[string]any {
	return generateVulnerabilities(level)
}

// generateTriageCluster creates a triage cluster.
func generateTriageCluster(level ExampleLevel) map[string]any {
	return map[string]any{
		"severity":    "critical",
		"count":       2,
		"fixable":     true,
		"findings":    generateVulnerabilities(ExampleLevelMinimal),
	}
}

// generateGraph creates full graph data.
func generateGraph(level ExampleLevel) map[string]any {
	return map[string]any{
		"nodes": generateGraphNodes(level),
		"edges": generateGraphEdges(level),
	}
}

// generateLayerDiff creates layer diff data.
func generateLayerDiff(level ExampleLevel) map[string]any {
	return map[string]any{
		"index":       0,
		"status":      "modified",
		"base_size":   10485760,
		"target_size": 12582912,
	}
}

// mustProtoToMap converts a proto message to a map, panicking on error.
// Used only for example generation where inputs are controlled.
func mustProtoToMap(msg proto.Message) map[string]any {
	m, err := ProtoToMap(msg)
	if err != nil {
		panic(fmt.Sprintf("mustProtoToMap: %v", err))
	}
	return m
}

// ListEntrypoints returns all available entrypoints sorted alphabetically.
func ListEntrypoints() []Entrypoint {
	eps := make([]Entrypoint, 0, len(BindingProfiles))
	for ep := range BindingProfiles {
		eps = append(eps, ep)
	}
	sort.Slice(eps, func(i, j int) bool {
		return string(eps[i]) < string(eps[j])
	})
	return eps
}

// GetCategoryForEntrypoint returns the category containing this entrypoint.
func GetCategoryForEntrypoint(ep Entrypoint) *ExampleCategory {
	for i := range ExampleCategories {
		for _, catEp := range ExampleCategories[i].Entrypoints {
			if catEp == ep {
				return &ExampleCategories[i]
			}
		}
	}
	return nil
}
