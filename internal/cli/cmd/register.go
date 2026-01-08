package cmd

import (
	"context"
	"log/slog"

	"github.com/picatz/deputy/internal/client"
	"github.com/picatz/deputy/internal/scan"
	"github.com/spf13/cobra"

	// Import AI providers to register them via init()
	_ "github.com/picatz/deputy/internal/ai/providers/claude"
	_ "github.com/picatz/deputy/internal/ai/providers/codex"
)

// Dependencies bundles shared services for CLI commands.
type Dependencies struct {
	// Client is the Deputy API client for service calls.
	// If nil, a default in-process client is created.
	Client client.Client

	// ClientOptions allows overriding client creation options.
	// Used when --server or --daemon flags are specified.
	ClientOptions client.Options
}

// RegisterCommands attaches all first-class subcommands to the provided root
// Cobra command. It centralizes subcommand registration for use by both the
// CLI entry point and tests.
func RegisterCommands(root *cobra.Command, deps Dependencies) {
	// Initialize client if not provided
	if deps.Client == nil {
		var err error
		deps.Client, err = client.New(context.Background(), deps.ClientOptions)
		if err != nil {
			// Fall back to in-process if auto-detection fails
			slog.Debug("client creation failed, falling back to in-process", "error", err)
			deps.Client = client.NewInProcess(nil)
		}
		slog.Debug("client initialized", "mode", deps.Client.Mode().String())
	}

	// Core workflow commands
	AddScanCommand(root, deps.Client)
	AddFixCommand(root, deps.Client)
	AddTriageCommand(root, deps.Client)
	AddDiffCommand(root, deps.Client)
	AddGraphCommand(root, deps.Client)

	// Supply chain commands
	AddSBOMCommand(root, deps.Client)
	AddListCommand(root, deps.Client)

	// Security scanning commands
	AddSecretsCommand(root, deps.Client)

	// Policy and enforcement commands
	AddPolicyCommand(root)
	AddProxyCommand(root)

	// Setup and configuration commands
	AddInitCommand(root)
	AddConfigCommand(root)

	// Informational commands
	AddVersionCommand(root)
	AddEcosystemsCommand(root, deps.Client)
	AddExplainCommand(root)

	// Integration commands
	AddMCPCommand(root)

	// Server command (uses scan.Service directly for handling requests)
	AddServerCommand(root, scan.NewService())
}
