package cmd

import (
	"fmt"
	"log/slog"

	"github.com/picatz/deputy/internal/policy/lsp"
	"github.com/spf13/cobra"
)

// newPolicyLSPCommand creates the `lsp` subcommand for starting the language server.
func newPolicyLSPCommand() *cobra.Command {
	var (
		useTCP   string
		logLevel string
	)
	cmd := &cobra.Command{
		Use:           "lsp",
		Short:         "Start the Deputy policy language server (YAML + CEL)",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			level := slog.LevelInfo
			switch logLevel {
			case "debug":
				level = slog.LevelDebug
			case "warn":
				level = slog.LevelWarn
			case "error":
				level = slog.LevelError
			case "", "info":
				level = slog.LevelInfo
			default:
				return fmt.Errorf("unknown log level %q", logLevel)
			}
			logger := slog.New(slog.NewTextHandler(cmd.ErrOrStderr(), &slog.HandlerOptions{Level: level}))
			opts := lsp.Options{
				UseStdio: useTCP == "",
				TCP:      useTCP,
				Log:      logger,
			}
			return lsp.Run(cmd.Context(), opts)
		},
	}
	cmd.Flags().StringVar(&useTCP, "tcp", "", "Listen on TCP address instead of stdio (e.g., 127.0.0.1:4389)")
	cmd.Flags().StringVar(&logLevel, "log-level", "info", "Logging level for the language server (debug|info|warn|error)")
	return cmd
}
