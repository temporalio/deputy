package analysis

import "testing"

func TestNewOSVClient_ConfiguresHTTPTimeout(t *testing.T) {
	c := NewOSVClient()
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
