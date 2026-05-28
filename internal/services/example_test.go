package services_test

import (
	"context"
	"fmt"
	"net/http"

	"connectrpc.com/connect"

	listv1 "github.com/temporalio/deputy/gen/deputy/list/v1"
	scanv1 "github.com/temporalio/deputy/gen/deputy/scan/v1"
	"github.com/temporalio/deputy/internal/services"
)

func Example_inProcess() {
	// Create services with local mode (default)
	svc, err := services.New()
	if err != nil {
		panic(err)
	}

	// Get in-process clients
	clients := svc.InProcessClients()

	// Use the generated client interface
	ctx := context.Background()
	resp, err := clients.Packages.ListEcosystems(ctx, connect.NewRequest(&listv1.ListEcosystemsRequest{}))
	if err != nil {
		panic(err)
	}

	fmt.Printf("Found %d ecosystems\n", len(resp.Msg.Ecosystems))
	// Output: Found 7 ecosystems
}

func Example_remote() {
	// Connect to a remote server
	clients := services.RemoteClients(http.DefaultClient, "https://deputy.example.com:8090")

	// Use the same interface as in-process
	ctx := context.Background()
	_, _ = clients.Vulns.Scan(ctx, connect.NewRequest(&scanv1.ScanRequest{
		Target: "github.com/example/repo",
	}))
	// Note: This would fail without a real server
}
