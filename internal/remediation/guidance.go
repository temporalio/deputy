package remediation

import (
	"fmt"
	"strings"
)

// GuidanceProfile identifies the caller surface that will present remediation
// commands. Hints should point to capabilities available on that surface.
type GuidanceProfile string

const (
	GuidanceProfileGeneric GuidanceProfile = "generic"
	GuidanceProfileCLI     GuidanceProfile = "cli"
	GuidanceProfileAPI     GuidanceProfile = "api"
	GuidanceProfileMCP     GuidanceProfile = "mcp"
)

// GuidanceCapabilities describes optional caller capabilities that can make a
// remediation hint more actionable.
type GuidanceCapabilities struct {
	GraphToolName string
	GraphService  bool
	ScanWithGraph bool
}

// GuidanceContext configures how remediation hints are adapted for a caller.
type GuidanceContext struct {
	Profile      GuidanceProfile
	Capabilities GuidanceCapabilities
}

// CLIGuidance returns guidance for Deputy command-line output. The CLI profile
// emits its own "deputy graph why" phrasing, so it does not set GraphToolName.
func CLIGuidance() GuidanceContext {
	return GuidanceContext{
		Profile: GuidanceProfileCLI,
		Capabilities: GuidanceCapabilities{
			ScanWithGraph: true,
		},
	}
}

// APIGuidance returns guidance for ConnectRPC clients.
func APIGuidance() GuidanceContext {
	return GuidanceContext{
		Profile: GuidanceProfileAPI,
		Capabilities: GuidanceCapabilities{
			GraphService: true,
		},
	}
}

// MCPGuidance returns guidance for MCP clients.
func MCPGuidance() GuidanceContext {
	return GuidanceContext{
		Profile: GuidanceProfileMCP,
		Capabilities: GuidanceCapabilities{
			GraphToolName: "graph_why",
		},
	}
}

// ApplyGuidance adapts generic remediation hints for the caller's capabilities.
func ApplyGuidance(commands []Command, guidance GuidanceContext) []Command {
	if len(commands) == 0 {
		return nil
	}
	out := make([]Command, len(commands))
	copy(out, commands)
	for i := range out {
		if hint := guidanceHint(out[i], guidance); hint != "" {
			out[i].Hint = hint
		}
	}
	return out
}

// guidanceHint returns a surface-specific hint for cmd when the caller can
// run graph queries, replacing the generic importer guidance. Returns "" when
// cmd does not need importer guidance, leaving the existing hint untouched.
func guidanceHint(cmd Command, guidance GuidanceContext) string {
	if !needsImporterGuidance(cmd) {
		return ""
	}
	query := commandQuery(cmd)
	switch {
	case guidance.Profile == GuidanceProfileCLI && query != "":
		if guidance.Capabilities.ScanWithGraph {
			return fmt.Sprintf("run deputy graph why %q --resolve-transitives to find the direct dependency that must migrate or update", query)
		}
		return fmt.Sprintf("run deputy graph why %q to find the direct dependency that must migrate or update", query)
	case strings.TrimSpace(guidance.Capabilities.GraphToolName) != "" && query != "":
		return fmt.Sprintf("use %s with package %q and resolveTransitives true to find the direct dependency that must migrate or update", guidance.Capabilities.GraphToolName, query)
	case guidance.Capabilities.GraphService && query != "":
		return fmt.Sprintf("call GraphService.WhyDependency for %q with GraphOptions.use_proxy and use_git enabled to find the direct dependency that must migrate or update", query)
	case guidance.Capabilities.ScanWithGraph && query != "":
		return fmt.Sprintf("use dependency graph context with transitive resolution for %q to find the direct dependency that must migrate or update", query)
	case query != "":
		return fmt.Sprintf("use dependency graph context for %q to find the direct dependency that must migrate or update", query)
	default:
		return "use dependency graph context to find the direct dependency that must migrate or update"
	}
}

// needsImporterGuidance reports whether cmd is an indirect migration fix that
// cannot be acted on without first finding the direct importer.
func needsImporterGuidance(cmd Command) bool {
	return cmd.Migration && !cmd.IsDirect && !cmd.Executable
}

// commandQuery returns the best graph query token for cmd: its PURL when
// known, otherwise the package name.
func commandQuery(cmd Command) string {
	if purl := strings.TrimSpace(cmd.PURL); purl != "" {
		return purl
	}
	return strings.TrimSpace(cmd.Package)
}
