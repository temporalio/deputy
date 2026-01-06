package ecosystem

import (
	"net/http"
	"testing"
)

// mockProxyHandler implements ProxyHandler for testing.
type mockProxyHandler struct {
	ecosystem Ecosystem
	upstream  string
}

func (h *mockProxyHandler) Ecosystem() Ecosystem { return h.ecosystem }
func (h *mockProxyHandler) DefaultUpstream() string { return h.upstream }
func (h *mockProxyHandler) ParseRequest(r *http.Request) (ProxyRequestInfo, error) {
	return ProxyRequestInfo{Name: "pkg", Version: "1.0.0", HasVersion: true, Operation: "download"}, nil
}
func (h *mockProxyHandler) ServeProxy(w http.ResponseWriter, r *http.Request, upstream string) error {
	return nil
}

// clearProxyRegistry clears the proxy registry before each test.
func clearProxyRegistry() {
	for k := range proxyRegistry {
		delete(proxyRegistry, k)
	}
}

func TestRegisterProxyHandler(t *testing.T) {
	clearProxyRegistry()

	h := &mockProxyHandler{
		ecosystem: "test-eco",
		upstream:  "https://test.example.com",
	}

	RegisterProxyHandler(h)

	got := GetProxyHandler("test-eco")
	if got == nil {
		t.Fatal("GetProxyHandler returned nil after registration")
	}
	if got.Ecosystem() != "test-eco" {
		t.Errorf("Ecosystem() = %q, want %q", got.Ecosystem(), "test-eco")
	}
	if got.DefaultUpstream() != "https://test.example.com" {
		t.Errorf("DefaultUpstream() = %q, want %q", got.DefaultUpstream(), "https://test.example.com")
	}
}

func TestRegisterProxyHandler_Duplicate(t *testing.T) {
	clearProxyRegistry()

	h1 := &mockProxyHandler{ecosystem: "dup-eco"}
	h2 := &mockProxyHandler{ecosystem: "dup-eco"}

	RegisterProxyHandler(h1)

	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on duplicate registration")
		}
	}()

	RegisterProxyHandler(h2) // Should panic
}

func TestGetProxyHandler_NotFound(t *testing.T) {
	clearProxyRegistry()

	got := GetProxyHandler("nonexistent")
	if got != nil {
		t.Errorf("GetProxyHandler(nonexistent) = %v, want nil", got)
	}
}

func TestHasProxySupport(t *testing.T) {
	clearProxyRegistry()

	RegisterProxyHandler(&mockProxyHandler{
		ecosystem: "with-proxy",
		upstream:  "https://proxy.example.com",
	})

	tests := []struct {
		eco  Ecosystem
		want bool
	}{
		{"with-proxy", true},
		{"nonexistent", false},
	}

	for _, tt := range tests {
		got := HasProxySupport(tt.eco)
		if got != tt.want {
			t.Errorf("HasProxySupport(%q) = %v, want %v", tt.eco, got, tt.want)
		}
	}
}

func TestAllProxyHandlers(t *testing.T) {
	clearProxyRegistry()

	handlers := []*mockProxyHandler{
		{ecosystem: "eco1", upstream: "https://eco1.example.com"},
		{ecosystem: "eco2", upstream: "https://eco2.example.com"},
		{ecosystem: "eco3", upstream: "https://eco3.example.com"},
	}

	for _, h := range handlers {
		RegisterProxyHandler(h)
	}

	all := AllProxyHandlers()
	if len(all) != 3 {
		t.Errorf("AllProxyHandlers() returned %d handlers, want 3", len(all))
	}
}

func TestProxySupportedEcosystems(t *testing.T) {
	clearProxyRegistry()

	RegisterProxyHandler(&mockProxyHandler{ecosystem: "eco-a"})
	RegisterProxyHandler(&mockProxyHandler{ecosystem: "eco-b"})

	ecosystems := ProxySupportedEcosystems()
	if len(ecosystems) != 2 {
		t.Errorf("ProxySupportedEcosystems() returned %d ecosystems, want 2", len(ecosystems))
	}

	// Check that both ecosystems are present (order is not guaranteed)
	found := make(map[Ecosystem]bool)
	for _, eco := range ecosystems {
		found[eco] = true
	}
	if !found["eco-a"] || !found["eco-b"] {
		t.Errorf("ProxySupportedEcosystems() = %v, want eco-a and eco-b", ecosystems)
	}
}

func TestProxyRequestInfo(t *testing.T) {
	info := ProxyRequestInfo{
		Name:       "express",
		Version:    "4.18.2",
		HasVersion: true,
		Operation:  "download",
	}

	if info.Name != "express" {
		t.Errorf("Name = %q, want %q", info.Name, "express")
	}
	if !info.HasVersion {
		t.Error("HasVersion = false, want true")
	}
	if info.Operation != "download" {
		t.Errorf("Operation = %q, want %q", info.Operation, "download")
	}
}

func TestProxyHandler_ParseRequest(t *testing.T) {
	h := &mockProxyHandler{
		ecosystem: "test",
		upstream:  "https://example.com",
	}

	info, err := h.ParseRequest(nil)
	if err != nil {
		t.Fatalf("ParseRequest error: %v", err)
	}
	if info.Name != "pkg" {
		t.Errorf("info.Name = %q, want %q", info.Name, "pkg")
	}
	if info.Version != "1.0.0" {
		t.Errorf("info.Version = %q, want %q", info.Version, "1.0.0")
	}
	if !info.HasVersion {
		t.Error("info.HasVersion = false, want true")
	}
}

// Test that the ProxyHandler interface can be properly implemented.
func TestProxyHandlerInterface(t *testing.T) {
	var h ProxyHandler = &mockProxyHandler{ecosystem: "test"}

	if h.Ecosystem() != "test" {
		t.Errorf("Ecosystem() = %q, want %q", h.Ecosystem(), "test")
	}
}
