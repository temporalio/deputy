package main_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	code := m.Run()
	if binPath != "" {
		_ = os.RemoveAll(filepath.Dir(binPath))
	}
	os.Exit(code)
}

var (
	buildOnce sync.Once
	binPath   string
	buildErr  error
)

func deputyBinary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		tmp, err := os.MkdirTemp("", "deputy-blackbox-*")
		if err != nil {
			buildErr = err
			return
		}
		binName := "deputy"
		if runtime.GOOS == "windows" {
			binName += ".exe"
		}
		binPath = filepath.Join(tmp, binName)

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "go", "build", "-o", binPath, ".")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			buildErr = err
			if stderr.Len() > 0 {
				buildErr = &execError{err: err, stderr: stderr.String()}
			}
		}
	})
	if buildErr != nil {
		t.Fatalf("build deputy: %v", buildErr)
	}
	return binPath
}

type execError struct {
	err    error
	stderr string
}

func (e *execError) Error() string { return e.err.Error() + ": " + e.stderr }

func runDeputy(t *testing.T, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	bin := deputyBinary(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = append(os.Environ(),
		"TERM=dumb",
		"CLICOLOR=0",
		"NO_COLOR=1",
	)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	err := cmd.Run()
	stdout, stderr = outBuf.String(), errBuf.String()
	if err == nil {
		return stdout, stderr, 0
	}
	var ee *exec.ExitError
	if !strings.Contains(err.Error(), "exit status") {
		t.Fatalf("run error: %v stderr=%q", err, stderr)
	}
	if errors.As(err, &ee) {
		return stdout, stderr, ee.ExitCode()
	}
	return stdout, stderr, 1
}

func TestBlackbox_Help(t *testing.T) {
	stdout, stderr, code := runDeputy(t, "--help")
	if code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, stderr)
	}
	if stderr != "" {
		t.Fatalf("unexpected stderr: %q", stderr)
	}
	if !strings.Contains(stdout, "Deputy is") {
		t.Fatalf("expected help text, got %q", stdout)
	}
}

func TestBlackbox_SilenceUsageOnFlagError(t *testing.T) {
	stdout, stderr, code := runDeputy(t, "scan", "--definitely-not-a-flag")
	if code == 0 {
		t.Fatalf("expected non-zero exit")
	}
	if stdout != "" {
		// errors should go to stderr (fang error handler)
		t.Fatalf("unexpected stdout: %q", stdout)
	}
	if strings.Contains(stderr, "Usage:") || strings.Contains(stderr, "Flags:") {
		t.Fatalf("expected no usage on error, stderr=%q", stderr)
	}
}

func TestBlackbox_TriageFromReport_StdoutOnly(t *testing.T) {
	reportPath := writeScanReportJSON(t, map[string]any{
		"repo":            "github.com/acme/repo",
		"ref":             "HEAD",
		"commit":          "deadbeef",
		"generated":       "2025-01-01T00:00:00Z",
		"packagesScanned": 1,
		"stats": map[string]any{
			"uniqueVulns":     1,
			"criticalSev":     1,
			"highSeverity":    0,
			"medSeverity":     0,
			"lowSeverity":     0,
			"fixAvailable":    1,
			"directDeps":      1,
			"indirectDeps":    0,
			"duplicatesFound": 0,
		},
		"vulnerabilities": []map[string]any{
			{
				"id":            "OSV-TEST-1",
				"package":       "github.com/acme/mod",
				"version":       "v1.0.0",
				"ecosystem":     "Go",
				"severity":      "9.8",
				"severityType":  "CVSS_V3",
				"fixedVersions": []string{"v1.0.1"},
				"isDirect":      true,
			},
		},
	})
	stdout, stderr, code := runDeputy(t, "triage", "--report", reportPath, "--format", "text")
	if code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, stderr)
	}
	if stderr != "" {
		t.Fatalf("unexpected stderr: %q", stderr)
	}
	if !strings.Contains(stdout, "Triage Summary:") {
		t.Fatalf("missing triage output, got %q", stdout)
	}
}

func TestBlackbox_FixFromReport_StdoutOnly(t *testing.T) {
	reportPath := writeScanReportJSON(t, map[string]any{
		"repo":            "github.com/acme/repo",
		"ref":             "HEAD",
		"commit":          "deadbeef",
		"generated":       "2025-01-01T00:00:00Z",
		"packagesScanned": 1,
		"stats": map[string]any{
			"uniqueVulns":     1,
			"criticalSev":     1,
			"highSeverity":    0,
			"medSeverity":     0,
			"lowSeverity":     0,
			"fixAvailable":    1,
			"directDeps":      1,
			"indirectDeps":    0,
			"duplicatesFound": 0,
		},
		"vulnerabilities": []map[string]any{
			{
				"id":            "OSV-TEST-1",
				"package":       "github.com/acme/mod",
				"version":       "v1.0.0",
				"ecosystem":     "Go",
				"severity":      "9.8",
				"severityType":  "CVSS_V3",
				"fixedVersions": []string{"v1.0.1"},
				"isDirect":      true,
			},
		},
	})
	stdout, stderr, code := runDeputy(t, "fix", "--report", reportPath, "--format", "text")
	if code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, stderr)
	}
	if stderr != "" {
		t.Fatalf("unexpected stderr: %q", stderr)
	}
	if !strings.Contains(stdout, "Remediation Plan:") {
		t.Fatalf("missing fix output, got %q", stdout)
	}
}

func writeScanReportJSON(t *testing.T, v any) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "scan-report.json")
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(p, append(b, '\n'), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}
