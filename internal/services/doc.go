// Package services provides the unified service layer for Deputy.
//
// This package implements a proto-first architecture where services directly
// implement ConnectRPC generated handler interfaces. The same implementations
// work both in-process (via InProcessTransport) and over the network
// (via standard HTTP/2).
//
// # Architecture
//
// The architecture follows idiomatic ConnectRPC patterns:
//
//	┌─────────────────────────────────────────────────────────────────┐
//	│                     Generated Interfaces                         │
//	│  scanv1connect.ScanServiceHandler / ScanServiceClient           │
//	│  listv1connect.ListServiceHandler / ListServiceClient           │
//	│  etc.                                                            │
//	└─────────────────────────────────────────────────────────────────┘
//	                              │
//	              ┌───────────────┴───────────────┐
//	              │                               │
//	              ▼                               ▼
//	┌─────────────────────────┐     ┌─────────────────────────┐
//	│    In-Process Mode      │     │      Remote Mode         │
//	│  (CLI, MCP, plugins)    │     │    (HTTP/2 server)       │
//	│                         │     │                          │
//	│  InProcessTransport     │     │  net/http + TLS          │
//	│  routes to handlers     │     │  routes to handlers      │
//	│  directly               │     │  over network            │
//	└─────────────────────────┘     └─────────────────────────┘
//
// # Usage
//
// Create services and use them in-process:
//
//	svc, err := services.New()
//	if err != nil {
//	    return err
//	}
//
//	// Get clients that call handlers directly
//	clients := svc.InProcessClients()
//
//	// Use standard ConnectRPC client interface
//	resp, err := clients.Scan.Scan(ctx, connect.NewRequest(&scanv1.ScanRequest{
//	    Target: ".",  // Local paths work in local mode
//	}))
//
// Connect to a remote server:
//
//	clients := services.RemoteClients(http.DefaultClient, "https://deputy.example.com:8090")
//
//	resp, err := clients.Scan.Scan(ctx, connect.NewRequest(&scanv1.ScanRequest{
//	    Target: "github.com/example/repo",  // Remote targets only
//	}))
//
// Mount services as HTTP handlers (for server mode):
//
//	svc, err := services.NewForServer()  // Enables remote target validation
//	mux := http.NewServeMux()
//	svc.RegisterHandlers(mux, connect.WithInterceptors(/* ... */))
//	http.ListenAndServe(":8090", mux)
//
// # Local vs Server Mode
//
// Services can operate in two modes:
//
//   - Local mode (default): Allows all targets including local filesystem paths.
//     Use services.New() for CLI, MCP, and other local consumers.
//
//   - Server mode: Validates that targets are remote-accessible (git URLs,
//     container registries, PURLs). Use services.NewForServer() for HTTP servers.
//
// # Benefits
//
// This architecture provides:
//
//   - Single implementation: Handlers work for both local and remote execution
//   - Generated interfaces: No manual client interface maintenance
//   - Type safety: Proto types throughout, no conversion errors
//   - Pluginrpc ready: Handlers can be exposed as plugins
//   - Zero overhead: In-process calls skip serialization
//
// # Migration from client.Client
//
// The old client.Client interface is deprecated. To migrate:
//
// Old:
//
//	c, err := client.New(ctx, client.Options{})
//	resp, err := c.Scan(ctx, req)
//
// New:
//
//	svc, err := services.New()
//	clients := svc.InProcessClients()
//	resp, err := clients.Scan.Scan(ctx, req)
//
// Or for remote:
//
//	clients := services.RemoteClients(http.DefaultClient, serverURL)
//	resp, err := clients.Scan.Scan(ctx, req)
//
// For code that still needs client.Client, use the adapter:
//
//	svc, err := services.New()
//	legacyClient := svc.LegacyClient()  // implements client.Client
package services
