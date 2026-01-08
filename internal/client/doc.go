// Package client provides the Deputy API client interface and implementations.
//
// The client package abstracts how CLI commands communicate with Deputy's core services.
// It supports three execution modes:
//
//   - In-Process (default): Direct function calls with zero serialization overhead.
//     This is the standard mode for CLI usage where no daemon or server is running.
//
//   - Local Daemon: Communication via Unix socket to a local Deputy daemon process.
//     Enables shared caching across invocations for better performance.
//
//   - Remote Server: Communication via HTTP/2 (ConnectRPC) to a remote Deputy server.
//     Enables centralized policy enforcement and enterprise features.
//
// # Mode Detection
//
// The client factory automatically detects the appropriate mode:
//
//  1. If DEPUTY_SERVER environment variable is set, use remote mode
//  2. If a daemon socket exists and is responsive, use daemon mode
//  3. Otherwise, use in-process mode (default)
//
// # Security Model
//
// Each execution mode has different security characteristics and supported target types:
//
// In-Process Mode:
//   - Full filesystem access (can scan local directories, files)
//   - Can access local Docker daemon (docker-daemon://)
//   - Can read local tarballs and OCI archives
//   - Can read stdin for SBOM input
//   - Target detection includes local filesystem heuristics
//
// Local Daemon Mode:
//   - Same capabilities as in-process (daemon runs locally)
//   - Can access local filesystem paths the daemon can see
//   - Caching benefits for repeated scans of same targets
//
// Remote Server Mode:
//   - Cannot access client's local filesystem
//   - Rejects: absolute paths (/path), relative paths (./), stdin (-)
//   - Rejects: docker-daemon://, tarball://, oci-archive://, oci-layout://
//   - Only accepts: git URLs, container registry refs, PURLs
//   - For SBOM analysis, use GenerateSBOM/DiffSBOM with uploaded bytes
//
// # Target Routing
//
// The client automatically routes scan requests to the appropriate scanner method
// based on target type detection or explicit TargetHint:
//
//   - pkg:... → PURL scan (ecosystem-specific vulnerability lookup)
//   - docker://, oci://, registry refs → Container image scan
//   - *.json, *.spdx, *.cdx → SBOM file scan
//   - Dockerfile, *.dockerfile → Dockerfile analysis
//   - github.com/... or bare directory → Git repository scan
//
// Clients can override auto-detection using ScanOptions.TargetHint for cases
// where the target string is ambiguous.
//
// # Usage
//
// The package provides multiple ways to create a client, from simple to explicit:
//
// Auto-detection (recommended for CLI tools):
//
//	client, err := client.NewAuto(ctx)
//	if err != nil {
//	    return err
//	}
//	defer client.Close()
//
// Explicit remote server:
//
//	client, err := client.ConnectToServer(ctx, "https://deputy.example.com:8090")
//
// Explicit local daemon:
//
//	client, err := client.ConnectToDaemon(ctx, "")  // default socket path
//
// Full control via Options:
//
//	client, err := client.New(ctx, client.Options{
//	    Mode:          client.ModeRemote,
//	    ForceMode:     true,
//	    ServerAddress: "https://deputy.example.com:8090",
//	})
//
// Performing a scan:
//
//	resp, err := client.Scan(ctx, connect.NewRequest(&scanv1.ScanRequest{
//	    Target: "github.com/owner/repo",
//	}))
//
// # Interface Design
//
// The Client interface mirrors the proto service definitions, enabling seamless
// switching between in-process and RPC modes without changing calling code.
// All methods accept proto request/response types for consistency.
//
// In-process mode avoids serialization by directly invoking internal services
// and converting types only at the boundary. This ensures CLI performance
// remains identical to the pre-client implementation.
//
// # CLI Integration
//
// The CLI uses a layered approach to target detection and scanning:
//
// For in-process mode (the 99% case), the CLI uses the Scanner interface
// directly via InProcess.Scanner(). This enables:
//   - Rich target detection with filesystem probing and git root detection
//   - Interactive ambiguity resolution (prompting users for clarification)
//   - Zero serialization overhead between CLI and scanner
//   - Access to internal types for rich output rendering
//
// For remote/daemon modes, the CLI uses the Client interface with proto types.
// Target detection in these modes is simpler and deterministic, relying on
// targets.DetectKind() for routing without filesystem access.
//
// This design intentionally separates concerns:
//   - Client layer: RPC abstraction with proto types, simple target routing
//   - CLI layer: Rich UX with filesystem awareness, ambiguity handling
//   - Scanner layer: Core scanning logic, internal types
//
// The targets package provides shared detection logic used by both the
// InProcess client and remote Server for consistent routing behavior.
package client
