package server

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// TestServer_H2C verifies that a non-TLS server speaks HTTP/2 cleartext (h2c)
// via the http.Server Protocols field while still serving HTTP/1.1 on the same
// listener. This pins the behavior that previously relied on h2c.NewHandler.
func TestServer_H2C(t *testing.T) {
	srv, err := New(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.httpServer.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.httpServer.Shutdown(ctx)
	})
	addr := ln.Addr().String()

	// h2c client: negotiate HTTP/2 over a plaintext TCP connection.
	h2cClient := &http.Client{
		Transport: &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, addr)
			},
		},
	}
	defer h2cClient.CloseIdleConnections()

	resp, err := h2cClient.Get("http://" + addr + "/health")
	if err != nil {
		t.Fatalf("h2c GET /health: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("h2c status = %d, want 200", resp.StatusCode)
	}
	if resp.ProtoMajor != 2 {
		t.Errorf("h2c proto = %q, want HTTP/2", resp.Proto)
	}

	// HTTP/1.1 must still work on the same listener.
	h1Client := &http.Client{}
	defer h1Client.CloseIdleConnections()

	resp1, err := h1Client.Get("http://" + addr + "/health")
	if err != nil {
		t.Fatalf("http/1.1 GET /health: %v", err)
	}
	defer resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Errorf("http/1.1 status = %d, want 200", resp1.StatusCode)
	}
	if resp1.ProtoMajor != 1 {
		t.Errorf("http/1.1 proto = %q, want HTTP/1.x", resp1.Proto)
	}
}
