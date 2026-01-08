package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/picatz/deputy/internal/logs"
	"github.com/picatz/deputy/internal/scan"
	"github.com/picatz/deputy/internal/server"
)

// serverFlags holds flags for the server command.
type serverFlags struct {
	addr         string
	readTimeout  time.Duration
	writeTimeout time.Duration
	idleTimeout  time.Duration
}

// AddServerCommand adds the server command to the root command.
func AddServerCommand(root *cobra.Command, scanService *scan.Service) {
	flags := &serverFlags{}

	cmd := &cobra.Command{
		Use:   "server",
		Short: "Start the Deputy gRPC/Connect server",
		Long: `Start the Deputy server which exposes scanning capabilities via gRPC and HTTP.

The server supports both gRPC and HTTP/JSON protocols via ConnectRPC, making it
accessible from various clients including:
  - gRPC clients (Go, Python, Java, etc.)
  - HTTP clients using JSON (curl, web browsers, etc.)
  - gRPC-Web clients (browser-based applications)

Examples:
  # Start server on default port (8090)
  deputy server

  # Start server on custom port
  deputy server --addr :9000

  # Start server with custom timeouts
  deputy server --write-timeout 10m

Endpoints:
  POST /deputy.v1.ScanService/Scan         - Perform vulnerability scan
  POST /deputy.v1.ScanService/StreamScan   - Scan with streaming progress
  GET  /health                              - Health check
  GET  /ready                               - Readiness check

Client example (curl):
  curl -X POST http://localhost:8090/deputy.v1.ScanService/Scan \
    -H "Content-Type: application/json" \
    -d '{"target": "."}'`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServer(cmd.Context(), flags, scanService)
		},
	}

	// Flags
	cmd.Flags().StringVar(&flags.addr, "addr", ":8090", "Address to listen on")
	cmd.Flags().DurationVar(&flags.readTimeout, "read-timeout", 30*time.Second, "Maximum duration for reading request")
	cmd.Flags().DurationVar(&flags.writeTimeout, "write-timeout", 5*time.Minute, "Maximum duration for writing response")
	cmd.Flags().DurationVar(&flags.idleTimeout, "idle-timeout", 2*time.Minute, "Maximum time to wait for next request")

	root.AddCommand(cmd)
}

func runServer(ctx context.Context, flags *serverFlags, scanService *scan.Service) error {
	cfg := server.Config{
		Addr:         flags.addr,
		Scanner:      scanService,
		ReadTimeout:  flags.readTimeout,
		WriteTimeout: flags.writeTimeout,
		IdleTimeout:  flags.idleTimeout,
	}

	srv := server.New(cfg)

	// Handle graceful shutdown
	shutdownCh := make(chan os.Signal, 1)
	signal.Notify(shutdownCh, os.Interrupt, syscall.SIGTERM)

	// Start server in background
	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil {
			errCh <- err
		}
	}()

	fmt.Fprintf(os.Stderr, "Deputy server listening on %s\n", flags.addr)
	fmt.Fprintf(os.Stderr, "Press Ctrl+C to stop\n")

	// Wait for shutdown signal or error
	select {
	case <-shutdownCh:
		logs.Info(ctx, "received shutdown signal")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		return fmt.Errorf("server error: %w", err)
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}
