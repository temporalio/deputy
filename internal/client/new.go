package client

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
)

// New creates a Client based on environment and options.
//
// Mode detection order (unless ForceMode is true):
//  1. If DEPUTY_SERVER env var is set, use remote mode
//  2. If daemon socket exists and is responsive, use daemon mode
//  3. Otherwise, use in-process mode (default)
//
// For simple use cases, prefer the convenience constructors:
//
//	client.NewAuto(ctx)              // automatic mode detection
//	client.NewInProcess(nil)         // always in-process
//	client.NewRemote(addr, false)    // connect to remote server
//	client.NewRemote(socket, true)   // connect to local daemon
func New(ctx context.Context, opts Options) (Client, error) {
	mode := opts.Mode
	if !opts.ForceMode {
		mode = detectMode(opts)
	}

	switch mode {
	case ModeInProcess:
		return NewInProcess(opts.Scanner), nil

	case ModeLocalDaemon:
		socket := opts.DaemonSocket
		if socket == "" {
			socket = defaultDaemonSocket()
		}
		return NewRemote(socket, true), nil

	case ModeRemote:
		addr := opts.ServerAddress
		if addr == "" {
			addr = os.Getenv("DEPUTY_SERVER")
		}
		if addr == "" {
			return nil, fmt.Errorf("remote mode requires server address (set DEPUTY_SERVER or Options.ServerAddress)")
		}
		return NewRemote(addr, false), nil

	default:
		return nil, fmt.Errorf("unknown mode: %d", mode)
	}
}

// detectMode determines the appropriate client mode based on environment.
func detectMode(opts Options) Mode {
	// Check for explicit server address
	if os.Getenv("DEPUTY_SERVER") != "" {
		return ModeRemote
	}

	// Check for local daemon socket
	socket := opts.DaemonSocket
	if socket == "" {
		socket = defaultDaemonSocket()
	}
	if isDaemonResponsive(socket) {
		return ModeLocalDaemon
	}

	// Default: in-process
	return ModeInProcess
}

// defaultDaemonSocket returns the default daemon socket path.
func defaultDaemonSocket() string {
	// Use XDG_RUNTIME_DIR if available (Linux), otherwise /tmp
	runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
	if runtimeDir == "" {
		runtimeDir = os.TempDir()
	}

	user := os.Getenv("USER")
	if user == "" {
		user = "deputy"
	}

	return filepath.Join(runtimeDir, fmt.Sprintf("deputy-%s", user), "daemon.sock")
}

// isDaemonResponsive checks if a daemon is listening on the socket.
func isDaemonResponsive(socketPath string) bool {
	// Check if socket file exists
	info, err := os.Stat(socketPath)
	if err != nil {
		return false
	}

	// Verify it's a socket
	if info.Mode()&os.ModeSocket == 0 {
		return false
	}

	// Try to connect with a short timeout
	conn, err := net.DialTimeout("unix", socketPath, 100*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// NewAuto creates a Client with automatic mode detection.
// This is the simplest way to create a client that adapts to its environment.
//
// Equivalent to: New(ctx, Options{})
func NewAuto(ctx context.Context) (Client, error) {
	return New(ctx, Options{})
}

// ConnectToServer creates a Client connected to a remote Deputy server.
//
// Example:
//
//	client, err := client.ConnectToServer(ctx, "https://deputy.example.com:8090")
func ConnectToServer(ctx context.Context, addr string) (Client, error) {
	return New(ctx, Options{
		Mode:          ModeRemote,
		ForceMode:     true,
		ServerAddress: addr,
	})
}

// ConnectToDaemon creates a Client connected to a local Deputy daemon.
// If socket is empty, uses the default socket path.
//
// Example:
//
//	client, err := client.ConnectToDaemon(ctx, "")  // default socket
//	client, err := client.ConnectToDaemon(ctx, "/custom/path.sock")
func ConnectToDaemon(ctx context.Context, socket string) (Client, error) {
	return New(ctx, Options{
		Mode:         ModeLocalDaemon,
		ForceMode:    true,
		DaemonSocket: socket,
	})
}
