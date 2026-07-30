package services

import (
	"net/http"
	"testing"

	"connectrpc.com/connect"

	listv1 "github.com/temporalio/deputy/gen/deputy/list/v1"
	"github.com/temporalio/deputy/gen/deputy/list/v1/listv1connect"
)

func TestInProcessTransport(t *testing.T) {
	// Create services
	svc, err := New()
	if err != nil {
		t.Fatalf("failed to create services: %v", err)
	}

	// Get in-process clients
	clients := svc.InProcessClients()

	// Test ListEcosystems (doesn't require target validation)
	ctx := t.Context()
	resp, err := clients.Packages.ListEcosystems(ctx, connect.NewRequest(&listv1.ListEcosystemsRequest{}))
	if err != nil {
		t.Fatalf("ListEcosystems failed: %v", err)
	}

	if len(resp.Msg.Ecosystems) == 0 {
		t.Error("expected at least one ecosystem")
	}

	// Verify some known ecosystems are present
	foundGo := false
	foundNpm := false
	for _, eco := range resp.Msg.Ecosystems {
		if eco.Name == "go" {
			foundGo = true
		}
		if eco.Name == "npm" {
			foundNpm = true
		}
	}

	if !foundGo {
		t.Error("expected 'go' ecosystem")
	}
	if !foundNpm {
		t.Error("expected 'npm' ecosystem")
	}
}

func TestInProcessTransport_NotFound(t *testing.T) {
	// Create transport with no handlers
	transport := NewInProcessTransport(nil)
	httpClient := transport.HTTPClient()

	// Try to call a service that's not registered
	client := listv1connect.NewListServiceClient(httpClient, "")

	_, err := client.ListEcosystems(t.Context(), connect.NewRequest(&listv1.ListEcosystemsRequest{}))
	if err == nil {
		t.Error("expected error for unregistered handler")
	}
}

func TestInProcessTransport_Mux(t *testing.T) {
	// Create a mux with a test handler
	mux := http.NewServeMux()
	mux.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	transport := NewInProcessTransport(mux)
	httpClient := transport.HTTPClient()

	req, _ := http.NewRequest("GET", "/test", nil)
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}
