package osv

import "testing"

func TestNewClient_ConfiguresHTTPTimeout(t *testing.T) {
	c := NewClient()
	if c == nil {
		t.Fatalf("expected client")
	}
	if c.HTTPClient == nil {
		t.Fatalf("expected HTTPClient")
	}
	if c.HTTPClient.Timeout <= 0 {
		t.Fatalf("expected positive timeout, got %v", c.HTTPClient.Timeout)
	}
}
