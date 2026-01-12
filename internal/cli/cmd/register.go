package cmd

import (
	"context"
	"log/slog"
	"net/http"
	"os"

	"connectrpc.com/connect"
	"github.com/picatz/deputy/internal/services"
	"github.com/spf13/cobra"

	// Import AI providers to register them via init()
	_ "github.com/picatz/deputy/internal/ai/providers/claude"
	_ "github.com/picatz/deputy/internal/ai/providers/codex"
)

// Dependencies bundles shared services for CLI commands.
type Dependencies struct {
	// Clients provides access to Deputy services.
	// If nil, default in-process clients are created.
	Clients *services.Clients

	// ServerAddress is the remote server address (for remote mode).
	// Can also be set via DEPUTY_SERVER environment variable.
	ServerAddress string

	// AuthToken is the bearer token for authenticating with remote servers.
	// Can also be set via DEPUTY_AUTH_TOKEN environment variable.
	AuthToken string
}

// RegisterCommands attaches all first-class subcommands to the provided root
// Cobra command. It centralizes subcommand registration for use by both the
// CLI entry point and tests.
func RegisterCommands(root *cobra.Command, deps Dependencies) {
	// Initialize clients if not provided
	if deps.Clients == nil {
		// Check for remote server
		serverAddr := deps.ServerAddress
		if serverAddr == "" {
			serverAddr = os.Getenv("DEPUTY_SERVER")
		}

		// Check for auth token
		authToken := deps.AuthToken
		if authToken == "" {
			authToken = os.Getenv("DEPUTY_AUTH_TOKEN")
		}

		if serverAddr != "" {
			// Remote mode - create clients with optional auth
			var opts []connect.ClientOption
			if authToken != "" {
				opts = append(opts, connect.WithInterceptors(authInterceptor(authToken)))
				slog.Debug("auth token configured for remote server")
			}
			deps.Clients = services.RemoteClients(http.DefaultClient, serverAddr, opts...)
			slog.Debug("clients initialized", "mode", "remote", "server", serverAddr)
		} else {
			// In-process mode (default)
			svc, err := services.New()
			if err != nil {
				slog.Error("failed to create services", "error", err)
				os.Exit(1)
			}
			deps.Clients = svc.InProcessClients()
			slog.Debug("clients initialized", "mode", "in-process")
		}
	}

	// Core workflow commands
	AddScanCommand(root, deps.Clients)
	AddFixCommand(root, deps.Clients)
	AddTriageCommand(root, deps.Clients)
	AddDiffCommand(root, deps.Clients)
	AddGraphCommand(root, deps.Clients)

	// Supply chain commands
	AddSBOMCommand(root, deps.Clients)
	AddListCommand(root, deps.Clients)

	// Security scanning commands
	AddSecretsCommand(root, deps.Clients)

	// Policy and enforcement commands
	AddPolicyCommand(root)
	AddProxyCommand(root)
	AddExecCommand(root, deps)

	// Setup and configuration commands
	AddInitCommand(root)
	AddConfigCommand(root)
	AddCacheCommand(root)

	// Informational commands
	AddVersionCommand(root)
	AddEcosystemsCommand(root, deps.Clients)
	AddExplainCommand(root)

	// Integration commands
	AddMCPCommand(root)

	// Server command
	AddServerCommand(root)
}

// authInterceptor returns a Connect interceptor that adds Bearer authentication.
func authInterceptor(token string) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			req.Header().Set("Authorization", "Bearer "+token)
			return next(ctx, req)
		}
	}
}
