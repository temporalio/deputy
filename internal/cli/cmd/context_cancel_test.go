package cmd

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/cobra"
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

	root := &cobra.Command{
		Use:           "deputy",
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	RegisterCommands(root)
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	root.SetArgs([]string{"proxy", "serve", "--config", cfgPath})

	done := make(chan error, 1)
	go func() {
		done <- root.ExecuteContext(ctx)
	}()

	time.Sleep(50 * time.Millisecond)
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

