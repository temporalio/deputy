package cmd

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/temporalio/deputy/internal/secrets"
)

type failingBaselineScanner struct {
	err error
}

func TestScanBaselineFileReturnsReadErrors(t *testing.T) {
	_, err := scanBaselineFile(t.Context(), fstest.MapFS{}, failingBaselineScanner{}, "missing.txt")
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("error = %v, want not-exist error", err)
	}
	if !strings.Contains(err.Error(), "reading missing.txt") {
		t.Fatalf("error = %q, want file context", err)
	}
}

func (s failingBaselineScanner) Scan(context.Context, []byte) ([]secrets.Finding, error) {
	return nil, s.err
}

func (s failingBaselineScanner) ScanFile(context.Context, string, []byte) ([]secrets.Finding, error) {
	return nil, s.err
}

func TestBaselineWalksSkipDirectorySymlinks(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target", filepath.Join(dir, "target-link")); err != nil {
		t.Skipf("creating directory symlink: %v", err)
	}

	scanner := failingBaselineScanner{err: errors.New("scanner should not be called")}
	tests := []struct {
		name string
		run  func() error
	}{
		{
			name: "create",
			run: func() error {
				_, err := generateBaselineWithExcludes(t.Context(), scanner, dir, "test", nil)
				return err
			},
		},
		{
			name: "update",
			run: func() error {
				_, err := scanDirectoryForBaseline(t.Context(), scanner, dir)
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.run(); err != nil {
				t.Fatalf("directory symlink caused baseline failure: %v", err)
			}
		})
	}
}

func TestBaselineWalksReturnScanErrors(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "credentials.txt"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	scanErr := errors.New("scanner unavailable")
	scanner := failingBaselineScanner{err: scanErr}

	tests := []struct {
		name string
		run  func() error
	}{
		{
			name: "create",
			run: func() error {
				_, err := generateBaselineWithExcludes(t.Context(), scanner, dir, "test", nil)
				return err
			},
		},
		{
			name: "update",
			run: func() error {
				_, err := scanDirectoryForBaseline(t.Context(), scanner, dir)
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.run()
			if !errors.Is(err, scanErr) {
				t.Fatalf("error = %v, want scanner error", err)
			}
			if !strings.Contains(err.Error(), "scanning credentials.txt") {
				t.Fatalf("error = %q, want file context", err)
			}
		})
	}
}
