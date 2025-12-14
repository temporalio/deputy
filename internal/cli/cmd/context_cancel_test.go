package cmd

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/picatz/deputy/internal/proxy"
)

func TestProxyServeHonorsContextCancellation(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	policyPath := filepath.Join(tmp, "allow-all.yaml")
	if err := os.WriteFile(policyPath, []byte(`
policies:
  - name: allow-all
    ecosystems: ["go"]
    rules:
      - action: allow
        when: true
`), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	cfgPath := filepath.Join(tmp, "proxy.yaml")
	if err := os.WriteFile(cfgPath, []byte(`
listeners:
  - name: go
    bind: "127.0.0.1:0"
    ecosystems: ["go"]
    upstream: "http://example.invalid"
    policies:
      - `+policyPath+`
`), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := proxy.LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	done := make(chan error, 1)
	started := make(chan struct{})
	server := proxy.NewServer(cfg, proxy.Options{
		OnListenerStart: func(_, _ string) {
			select {
			case <-started:
			default:
				close(started)
			}
		},
	})
	go func() {
		done <- server.Serve(ctx)
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for proxy serve to start")
	}

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("execute error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for proxy serve to exit after cancel")
	}
}
