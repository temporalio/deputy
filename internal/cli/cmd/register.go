package cmd

import (
	"github.com/picatz/deputy/internal/scan"
	"github.com/spf13/cobra"
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
	AddScanCommand(root, deps.ScanService)
	AddFixCommand(root, deps.ScanService)
	AddTriageCommand(root, deps.ScanService)
	AddSBOMCommand(root)
	AddDiffCommand(root, deps.ScanService)
	AddListCommand(root)
	AddPolicyCommand(root)
	AddProxyCommand(root)
}
