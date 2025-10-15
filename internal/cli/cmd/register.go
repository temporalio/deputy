package cmd

import "github.com/spf13/cobra"

// RegisterCommands attaches all first-class subcommands to the provided root
// Cobra command. It centralizes subcommand registration for use by both the
// CLI entry point and tests.
func RegisterCommands(root *cobra.Command) {
	AddScanCommand(root)
	AddSBOMCommand(root)
	AddDiffCommand(root)
	AddListCommand(root)
	AddIndexCommand(root)
}
