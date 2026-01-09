// Package server provides the Deputy gRPC/Connect server implementation.
//
// The server exposes all Deputy capabilities via ConnectRPC, supporting both
// gRPC and HTTP/JSON protocols. This enables remote access from various clients
// including CLI tools, web applications, and CI/CD pipelines.
//
// # Services
//
// The server provides seven main services:
//
//   - ScanService: Vulnerability scanning - finds CVEs and advisories in dependencies
//   - SecretsService: Secret detection - finds leaked credentials and API keys
//   - ListService: Package enumeration - lists dependencies and ecosystems
//   - SBOMService: SBOM generation - creates and compares Software Bills of Materials
//   - RemediationService: Fix planning - generates and executes remediation plans
//   - DiffService: Dependency comparison - compares packages and vulnerabilities between targets
//   - GraphService: Dependency graph analysis - builds and queries dependency graphs
//
// # Architecture
//
// Each service has a dedicated handler that wraps Deputy's internal packages
// and exposes them via ConnectRPC. Bidirectional type converters in internal/proto
// handle translation between proto messages and internal domain types.
//
// Handler implementations:
//   - scan_handler.go: Vulnerability scanning via internal/scan
//   - list_handler.go: Package listing via internal/inventory
//   - sbom_handler.go: SBOM generation via internal/sbom
//   - remediation_handler.go: Fix planning via internal/remediation
//   - secrets_handler.go: Secret detection via internal/secrets
//   - diff_handler.go: Dependency comparison via internal/compare
//   - graph_handler.go: Dependency graph via internal/dependency/graph
//
// # Starting the Server
//
//	srv := server.New(server.Config{
//	    Addr: ":8090",
//	})
//	if err := srv.ListenAndServe(); err != nil {
//	    log.Fatal(err)
//	}
//
// # Configuration
//
// The server supports various configuration options:
//
//	cfg := server.Config{
//	    Addr:         ":8090",           // Listen address
//	    Scanner:      scanService,       // Custom scan.Service implementation
//	    ReadTimeout:  30 * time.Second,  // Request read timeout
//	    WriteTimeout: 5 * time.Minute,   // Response write timeout
//	    IdleTimeout:  2 * time.Minute,   // Idle connection timeout
//	    TLS:          &server.TLSConfig{...}, // Optional TLS
//	    CORS:         &server.CORSConfig{...}, // Optional CORS
//	    Auth:         &server.AuthConfig{...}, // Optional JWT auth
//	    RateLimit:    &server.RateLimitConfig{...}, // Optional rate limiting
//	}
//
// # Client Usage
//
// Clients can connect using any ConnectRPC-compatible client:
//
//	// Scan for VULNERABILITIES (CVEs in dependencies)
//	scanClient := scanv1connect.NewScanServiceClient(
//	    http.DefaultClient,
//	    "http://localhost:8090",
//	)
//	resp, err := scanClient.Scan(ctx, connect.NewRequest(&scanv1.ScanRequest{
//	    Target: "github.com/example/repo",
//	}))
//
//	// Scan for SECRETS (leaked credentials, API keys)
//	secretsClient := secretsv1connect.NewSecretsServiceClient(
//	    http.DefaultClient,
//	    "http://localhost:8090",
//	)
//	resp, err := secretsClient.Scan(ctx, connect.NewRequest(&secretsv1.ScanRequest{
//	    Target: "github.com/example/repo",
//	}))
//
// # HTTP Endpoints
//
// In addition to the gRPC services, the server exposes health check endpoints:
//
//	GET /health  - Returns {"status":"ok"} when healthy
//	GET /ready   - Returns {"status":"ready"} when ready
//	GET /version - Returns API version information
package server
