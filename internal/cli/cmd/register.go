package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"connectrpc.com/connect"
	"github.com/spf13/cobra"
	"github.com/temporalio/deputy/internal/services"

	// Import AI providers to register them via init()
	_ "github.com/temporalio/deputy/internal/ai/providers/claude"
	_ "github.com/temporalio/deputy/internal/ai/providers/codex"
)

// Dependencies bundles shared services for CLI commands.
//
// Connection settings resolve with explicit-value precedence: a value set on
// the struct (typically from a root persistent flag) beats the corresponding
// environment variable, and the environment variable beats the in-process
// default.
type Dependencies struct {
	// Clients provides access to Deputy services.
	// If nil, RegisterCommands creates them via ResolveConnection.
	Clients *services.Clients

	// ServerAddress is the remote server address (for remote mode).
	// Falls back to the DEPUTY_SERVER environment variable when empty.
	ServerAddress string

	// AuthToken is the bearer token for authenticating with remote servers.
	// Falls back to the DEPUTY_AUTH_TOKEN environment variable when empty.
	AuthToken string
}

// ResolveConnection fills empty connection settings from the environment
// (explicit value beats environment variable beats in-process default) and
// builds the matching service clients via ApplyConnection.
func (d *Dependencies) ResolveConnection() error {
	if d.ServerAddress == "" {
		d.ServerAddress = os.Getenv("DEPUTY_SERVER")
	}
	if d.AuthToken == "" {
		d.AuthToken = os.Getenv("DEPUTY_AUTH_TOKEN")
	}
	return d.ApplyConnection()
}

// ApplyConnection builds service clients from the connection settings as they
// stand, without consulting the environment: an empty ServerAddress selects
// in-process mode and an empty AuthToken sends no bearer token. It exists so
// the root command can re-apply the settings after cobra has parsed the
// persistent flags (commands are registered before parsing) and honor flags
// that were explicitly set to empty values over environment variables. When
// d.Clients is already set, the pointed-to struct is updated in place so
// every command closure that captured the pointer at registration time
// observes the new configuration.
func (d *Dependencies) ApplyConnection() error {
	var clients *services.Clients
	if d.ServerAddress != "" {
		// Remote mode with optional bearer auth.
		var opts []connect.ClientOption
		if d.AuthToken != "" {
			opts = append(opts, connect.WithInterceptors(authInterceptor(d.AuthToken)))
			slog.Debug("auth token configured for remote server")
		}
		clients = services.RemoteClients(http.DefaultClient, d.ServerAddress, opts...)
		slog.Debug("clients initialized", "mode", "remote", "server", d.ServerAddress)
	} else {
		// In-process mode (default).
		svc, err := services.New()
		if err != nil {
			return fmt.Errorf("create in-process services: %w", err)
		}
		clients = svc.InProcessClients()
		slog.Debug("clients initialized", "mode", "in-process")
	}

	// Copy in place rather than reassigning d.Clients: RegisterCommands hands
	// the pointer to every command at registration time, which happens before
	// cobra parses flags, so those commands would keep the pre-flag clients if
	// this rebound the field. Pointer identity is the contract, see
	// TestApplyConnectionKeepsClientsPointer.
	if d.Clients == nil {
		d.Clients = clients
	} else {
		*d.Clients = *clients
	}
	return nil
}

// RegisterCommands attaches all first-class subcommands to the provided root
// Cobra command. It centralizes subcommand registration for use by both the
// CLI entry point and tests. deps is a pointer so callers can re-resolve the
// connection after flag parsing (see Dependencies.ResolveConnection) and have
// the registered commands observe the update.
func RegisterCommands(root *cobra.Command, deps *Dependencies) {
	if deps == nil {
		deps = &Dependencies{}
	}
	// Initialize clients if not provided.
	if deps.Clients == nil {
		if err := deps.ResolveConnection(); err != nil {
			slog.Error("failed to create services", "error", err)
			os.Exit(1)
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
	AddPinCommand(root)

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
