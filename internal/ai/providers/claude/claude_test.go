package claude

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/temporalio/deputy/internal/ai"
)

func TestStreamStopOnProcessError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test uses a POSIX shell script")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "claude"), []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)

	for event, err := range (&Provider{}).Stream(t.Context(), &ai.CompletionRequest{}) {
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := event.(ai.ErrorEvent); !ok {
			t.Fatalf("got %T, want ai.ErrorEvent", event)
		}
		return
	}
	t.Fatal("stream ended before reporting the process error")
}
