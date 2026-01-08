// Package server provides the Deputy gRPC/Connect server implementation.
//
// The server exposes Deputy's scanning capabilities via ConnectRPC, supporting
// both gRPC and HTTP/JSON protocols. This enables remote scanning from various
// clients including CLI tools, web applications, and CI/CD pipelines.
//
// # Architecture
//
// The server wraps Deputy's internal scan service and exposes it via the
// ScanService defined in api/deputy/scan/v1/scan.proto. Bidirectional type
// converters in internal/proto handle translation between proto messages
// and internal domain types.
//
// # Starting the Server
//
//	server := server.New(server.Config{
//	    Addr: ":8090",
//	})
//	if err := server.ListenAndServe(); err != nil {
//	    log.Fatal(err)
//	}
//
// # Client Usage
//
// Clients can connect using any ConnectRPC-compatible client:
//
//	client := scanv1connect.NewScanServiceClient(
//	    http.DefaultClient,
//	    "http://localhost:8090",
//	)
//	resp, err := client.Scan(ctx, connect.NewRequest(&scanv1.ScanRequest{
//	    Target: "github.com/example/repo",
//	}))
package server
