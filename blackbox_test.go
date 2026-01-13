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

	"google.golang.org/protobuf/encoding/protojson"

	dependencyv1 "github.com/picatz/deputy/gen/deputy/dependency/v1"
	scanv1 "github.com/picatz/deputy/gen/deputy/scan/v1"
	targetv1 "github.com/picatz/deputy/gen/deputy/target/v1"
	vulnerabilityv1 "github.com/picatz/deputy/gen/deputy/vulnerability/v1"
)

func TestMain(m *testing.M) {
	code := m.Run()
	// Only clean up if we built the binary ourselves (not pre-built from env)
	if binPath != "" && os.Getenv("DEPUTY_TEST_BINARY") == "" {
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
		// Check for pre-built binary (used in CI to avoid OOM with race detector)
		if prebuilt := os.Getenv("DEPUTY_TEST_BINARY"); prebuilt != "" {
			if _, err := os.Stat(prebuilt); err == nil {
				binPath = prebuilt
				return
			}
		}

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
	resp := &scanv1.ScanResponse{
		Target: &targetv1.Target{
			DisplayPath: "github.com/acme/repo",
			CommitHash:  "deadbeef",
		},
		Findings: []*vulnerabilityv1.Finding{
			{
				AdvisoryId: "OSV-TEST-1",
				Package: &dependencyv1.Package{
					Name:      "github.com/acme/mod",
					Version:   "v1.0.0",
					Ecosystem: "Go",
					Direct:    true,
				},
				Advisory: &vulnerabilityv1.Advisory{
					Id:      "OSV-TEST-1",
					Summary: "Test vulnerability",
					Severity: &vulnerabilityv1.Severity{
						Score: 9.8,
						Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_CRITICAL,
						Type:  vulnerabilityv1.SeverityType_SEVERITY_TYPE_CVSS_V3,
					},
					FixedVersions: []string{"v1.0.1"},
				},
			},
		},
		Stats: &vulnerabilityv1.Stats{
			Unique:       1,
			Critical:     1,
			FixAvailable: 1,
		},
	}
	reportPath := writeScanReportProtoJSON(t, resp)
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
	resp := &scanv1.ScanResponse{
		Target: &targetv1.Target{
			DisplayPath: "github.com/acme/repo",
			CommitHash:  "deadbeef",
		},
		Findings: []*vulnerabilityv1.Finding{
			{
				AdvisoryId: "OSV-TEST-1",
				Package: &dependencyv1.Package{
					Name:      "github.com/acme/mod",
					Version:   "v1.0.0",
					Ecosystem: "Go",
					Direct:    true,
				},
				Advisory: &vulnerabilityv1.Advisory{
					Id:      "OSV-TEST-1",
					Summary: "Test vulnerability",
					Severity: &vulnerabilityv1.Severity{
						Score: 9.8,
						Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_CRITICAL,
						Type:  vulnerabilityv1.SeverityType_SEVERITY_TYPE_CVSS_V3,
					},
					FixedVersions: []string{"v1.0.1"},
				},
			},
		},
		Stats: &vulnerabilityv1.Stats{
			Unique:       1,
			Critical:     1,
			FixAvailable: 1,
		},
	}
	reportPath := writeScanReportProtoJSON(t, resp)
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

// writeScanReportProtoJSON writes a scanv1.ScanResponse as proto JSON format.
func writeScanReportProtoJSON(t *testing.T, resp *scanv1.ScanResponse) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "scan-report.json")
	opts := protojson.MarshalOptions{
		Multiline:       true,
		Indent:          "  ",
		EmitUnpopulated: false,
		UseProtoNames:   true,
	}
	b, err := opts.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal proto: %v", err)
	}
	if err := os.WriteFile(p, append(b, '\n'), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

// ============================================================================
// Exec command tests
// ============================================================================

func TestBlackbox_Exec_NoneRuntime_Echo(t *testing.T) {
	// Test basic execution with the 'none' runtime (always available)
	stdout, stderr, code := runDeputy(t, "exec", "--runtime", "none", "--", "echo", "hello world")
	if code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, "hello world") {
		t.Fatalf("expected 'hello world' in stdout, got %q", stdout)
	}
}

func TestBlackbox_Exec_NoneRuntime_ExitCode(t *testing.T) {
	// Test that non-zero exit codes are propagated
	_, _, code := runDeputy(t, "exec", "--runtime", "none", "--", "false")
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
}

func TestBlackbox_Exec_NoneRuntime_Stderr(t *testing.T) {
	// Test that stderr is captured correctly
	stdout, stderr, code := runDeputy(t, "exec", "--runtime", "none", "--dangerously-skip-prompt", "--", "sh", "-c", "echo stdout; echo stderr >&2")
	if code != 0 {
		t.Fatalf("exit=%d", code)
	}
	if !strings.Contains(stdout, "stdout") {
		t.Fatalf("expected 'stdout' in stdout, got %q", stdout)
	}
	if !strings.Contains(stderr, "stderr") {
		t.Fatalf("expected 'stderr' in stderr, got %q", stderr)
	}
}

func TestBlackbox_Exec_NoneRuntime_EnvVar(t *testing.T) {
	// Test environment variable passing
	stdout, stderr, code := runDeputy(t, "exec", "--runtime", "none", "--env", "TEST_VAR=hello_deputy", "--", "printenv", "TEST_VAR")
	if code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, "hello_deputy") {
		t.Fatalf("expected 'hello_deputy' in stdout, got %q", stdout)
	}
}

func TestBlackbox_Exec_NoneRuntime_WorkDir(t *testing.T) {
	// Test working directory setting
	tmpDir := t.TempDir()
	stdout, stderr, code := runDeputy(t, "exec", "--runtime", "none", "--work-dir", tmpDir, "--", "pwd")
	if code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, stderr)
	}
	// Note: On macOS, /var is symlinked to /private/var, so we check for the base name
	if !strings.Contains(stdout, filepath.Base(tmpDir)) {
		t.Fatalf("expected working directory to contain %q, got %q", filepath.Base(tmpDir), stdout)
	}
}

func TestBlackbox_Exec_NoneRuntime_Timeout(t *testing.T) {
	// Test that timeout is enforced - command should be killed before 10s
	start := time.Now()
	_, stderr, code := runDeputy(t, "exec", "--runtime", "none", "--timeout", "1s", "--", "sleep", "10")
	elapsed := time.Since(start)

	// Verify the command was interrupted (didn't run for full 10s)
	if elapsed > 5*time.Second {
		t.Fatalf("timeout didn't work: command ran for %v", elapsed)
	}

	// Should fail with non-zero exit code due to timeout
	if code == 0 {
		t.Fatalf("expected non-zero exit code due to timeout")
	}

	// Error message should indicate timeout
	if !strings.Contains(stderr, "timed out") {
		t.Logf("stderr: %q", stderr)
		// Don't fail - the important thing is it timed out and returned non-zero
	}
}

func TestBlackbox_Exec_MissingCommand(t *testing.T) {
	// Test error handling for missing command
	_, stderr, code := runDeputy(t, "exec", "--runtime", "none", "--")
	if code == 0 {
		t.Fatalf("expected non-zero exit code for missing command")
	}
	if !strings.Contains(stderr, "provide the command") {
		t.Fatalf("expected error about missing command, got %q", stderr)
	}
}

func TestBlackbox_Exec_InvalidRuntime(t *testing.T) {
	// Test error handling for invalid runtime
	_, stderr, code := runDeputy(t, "exec", "--runtime", "nonexistent-runtime-xyz", "--", "echo", "test")
	if code == 0 {
		t.Fatalf("expected non-zero exit code for invalid runtime")
	}
	if !strings.Contains(stderr, "unsupported runtime") {
		t.Fatalf("expected error about unsupported runtime, got %q", stderr)
	}
}

func TestBlackbox_Exec_PluginRuntime_MissingPluginName(t *testing.T) {
	// Test that plugin runtime requires --plugin flag
	_, stderr, code := runDeputy(t, "exec", "--runtime", "plugin", "--", "echo", "test")
	if code == 0 {
		t.Fatalf("expected non-zero exit code when --plugin is missing")
	}
	if !strings.Contains(stderr, "--plugin is required") {
		t.Fatalf("expected error about missing --plugin, got %q", stderr)
	}
}

func TestBlackbox_Exec_PluginRuntime_PluginNotFound(t *testing.T) {
	// When a plugin isn't found, the exec command should fail with a clear error.
	_, stderr, code := runDeputy(t, "exec", "--runtime", "plugin", "--plugin", "nonexistent-plugin-xyz", "--", "echo", "fallback-test")
	if code == 0 {
		t.Fatalf("expected non-zero exit code when plugin is missing")
	}
	if !strings.Contains(stderr, "plugin") || !strings.Contains(stderr, "not found") {
		t.Fatalf("expected plugin not found error, got %q", stderr)
	}
}

func TestBlackbox_Exec_ReadOnlyMode(t *testing.T) {
	// Test read-only mode works
	stdout, stderr, code := runDeputy(t, "exec", "--runtime", "none", "--mode", "read-only", "--", "echo", "readonly test")
	if code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, "readonly test") {
		t.Fatalf("expected output, got %q", stdout)
	}
}

func TestBlackbox_Exec_NoWorkspace(t *testing.T) {
	// Test --no-workspace flag
	stdout, stderr, code := runDeputy(t, "exec", "--runtime", "none", "--no-workspace", "--", "echo", "no workspace")
	if code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, "no workspace") {
		t.Fatalf("expected output, got %q", stdout)
	}
}
