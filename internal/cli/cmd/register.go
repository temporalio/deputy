package cmd

import (
	"github.com/picatz/deputy/internal/scan"
	"github.com/spf13/cobra"

	// Import AI providers to register them via init()
	_ "github.com/picatz/deputy/internal/ai/providers/claude"
	_ "github.com/picatz/deputy/internal/ai/providers/codex"
)

// Dependencies bundles shared services for CLI commands.
type Dependencies struct {
	ScanService *scan.Service
}

// RegisterCommands attaches all first-class subcommands to the provided root
// Cobra command. It centralizes subcommand registration for use by both the
// CLI entry point and tests.
func RegisterCommands(root *cobra.Command, deps Dependencies) {
	if deps.ScanService == nil {
		deps.ScanService = scan.NewService()
	}

	// Core workflow commands
	AddScanCommand(root, deps.ScanService)
	AddFixCommand(root, deps.ScanService)
	AddTriageCommand(root, deps.ScanService)
	AddDiffCommand(root, deps.ScanService)
	AddGraphCommand(root)

	// Supply chain commands
	AddSBOMCommand(root)
	AddListCommand(root)

	// Policy and enforcement commands
	AddPolicyCommand(root)
	AddProxyCommand(root)

	// Setup and configuration commands
	AddInitCommand(root)
	AddConfigCommand(root)

	// Informational commands
	AddVersionCommand(root)
	AddEcosystemsCommand(root)
	AddExplainCommand(root)

	// Integration commands
	AddMCPCommand(root)
}
