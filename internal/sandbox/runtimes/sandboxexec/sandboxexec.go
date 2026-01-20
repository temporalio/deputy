// Package sandboxexec provides a macOS sandbox-exec runtime.
//
// Note: sandbox-exec is deprecated by Apple and provides best-effort isolation.
// It is useful for lightweight macOS sandboxing but should not be treated as a
// strong security boundary.
package sandboxexec

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	sandboxv1 "github.com/picatz/deputy/gen/deputy/sandbox/v1"
	"github.com/picatz/deputy/internal/sandbox"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const sandboxExecBinary = "sandbox-exec"

var (
	// defaultReadPaths are system paths needed for basic operation.
	// User-specific paths should be added via --read-path or --profile flags.
	defaultReadPaths = []string{
		"/bin",
		"/usr/bin",
		"/usr/sbin",
		"/sbin",
		"/usr/lib",
		"/usr/share",
		"/System",
		"/Library",
		"/etc",
		"/private/etc",
		"/usr/local",
		"/opt/homebrew",
	}
	// defaultExecPaths are system paths for executable lookup.
	// Additional exec paths should be added via --exec-path or --profile flags.
	defaultExecPaths = []string{
		"/bin",
		"/usr/bin",
		"/usr/sbin",
		"/sbin",
		"/usr/local/bin",
		"/opt/homebrew/bin",
		// Homebrew uses symlinks from bin/ to Cellar/ and Caskroom/
		// We need to allow execution from these directories too
		"/opt/homebrew/Cellar",
		"/opt/homebrew/Caskroom",
	}
)

type pathSpec struct {
	Path    string
	Literal bool
}

// Runtime implements sandbox.Runtime using sandbox-exec on macOS.
type Runtime struct {
	logger *slog.Logger
}

// Option configures the sandbox-exec runtime.
type Option func(*Runtime)

// WithLogger sets the logger used for runtime diagnostics.
func WithLogger(logger *slog.Logger) Option {
	return func(r *Runtime) {
		if logger != nil {
			r.logger = logger
		}
	}
}

// New creates a new sandbox-exec runtime.
func New(opts ...Option) *Runtime {
	r := &Runtime{
		logger: slog.Default(),
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Ensure Runtime implements sandbox.Runtime.
var _ sandbox.Runtime = (*Runtime)(nil)

// Name returns RUNTIME_SANDBOX_EXEC.
func (r *Runtime) Name() sandboxv1.Runtime {
	return sandboxv1.Runtime_RUNTIME_SANDBOX_EXEC
}

// Info returns metadata about the sandbox-exec runtime.
func (r *Runtime) Info(ctx context.Context) (*sandboxv1.RuntimeInfo, error) {
	available := r.Available(ctx)
	info := &sandboxv1.RuntimeInfo{
		Runtime:        sandboxv1.Runtime_RUNTIME_SANDBOX_EXEC,
		DisplayName:    "macOS sandbox-exec (deprecated)",
		Version:        r.Version(ctx),
		Available:      available,
		SupportedModes: supportedModes(),
		Capabilities:   r.Capabilities(),
	}
	if !available {
		if runtime.GOOS != "darwin" {
			info.UnavailableReason = "sandbox-exec is only available on macOS"
		} else {
			info.UnavailableReason = "sandbox-exec binary not found"
		}
	}
	return info, nil
}

// Available returns true if sandbox-exec is available on macOS.
func (r *Runtime) Available(ctx context.Context) bool {
	if runtime.GOOS != "darwin" {
		return false
	}
	_, err := exec.LookPath(sandboxExecBinary)
	return err == nil
}

// Version returns the sandbox-exec version string, if available.
func (r *Runtime) Version(ctx context.Context) string {
	return ""
}

// Capabilities returns what this runtime supports.
func (r *Runtime) Capabilities() *sandboxv1.RuntimeCapabilities {
	return &sandboxv1.RuntimeCapabilities{
		NetworkIsolation:    true,
		FilesystemIsolation: true,
		ResourceLimits:      false,
		Seccomp:             false,
		Apparmor:            false,
		Selinux:             false,
		UserNamespaces:      false,
		Rootless:            true,
		GpuSupport:          false,
		StreamingOutput:     true,
		InteractiveStdin:    true,
	}
}

// Execute runs a command in a sandbox-exec sandbox.
func (r *Runtime) Execute(ctx context.Context, req *sandboxv1.ExecuteRequest) iter.Seq2[*sandboxv1.ExecuteEvent, error] {
	return func(yield func(*sandboxv1.ExecuteEvent, error) bool) {
		executionID := sandbox.GenerateExecutionID("sandbox-exec")
		startTime := time.Now()

		if runtime.GOOS != "darwin" {
			yield(errorEvent(executionID, "UNSUPPORTED_PLATFORM", "sandbox-exec is only available on macOS", true), nil)
			return
		}

		if len(req.GetCommand()) == 0 {
			yield(errorEvent(executionID, "INVALID_REQUEST", "command is required", true), nil)
			return
		}

		if err := sandbox.ValidateCommand(req.GetCommand()); err != nil {
			r.logger.WarnContext(ctx, "command blocked by security policy",
				"execution_id", executionID,
				"command", req.GetCommand()[0],
				"reason", err.Error(),
			)
			yield(errorEvent(executionID, "COMMAND_BLOCKED", err.Error(), true), nil)
			return
		}

		if err := sandbox.ValidatePath(req.GetWorkspaceDir()); err != nil {
			r.logger.WarnContext(ctx, "path blocked by security policy",
				"execution_id", executionID,
				"path", req.GetWorkspaceDir(),
				"reason", err.Error(),
			)
			yield(errorEvent(executionID, "PATH_BLOCKED", err.Error(), true), nil)
			return
		}

		if err := sandbox.ValidatePath(req.GetWorkDir()); err != nil {
			r.logger.WarnContext(ctx, "workdir blocked by security policy",
				"execution_id", executionID,
				"path", req.GetWorkDir(),
				"reason", err.Error(),
			)
			yield(errorEvent(executionID, "PATH_BLOCKED", err.Error(), true), nil)
			return
		}

		cfg := req.GetConfig()
		if cfg == nil {
			cfg = &sandboxv1.SandboxConfig{}
		}

		if err := validateConfig(cfg); err != nil {
			yield(errorEvent(executionID, "UNSUPPORTED_CONFIG", err.Error(), true), nil)
			return
		}

		profile, err := buildProfile(cfg, req.GetWorkspaceDir())
		if err != nil {
			yield(errorEvent(executionID, "PROFILE_ERROR", err.Error(), true), nil)
			return
		}

		profilePath, err := writeProfile(profile)
		if err != nil {
			yield(errorEvent(executionID, "PROFILE_ERROR", err.Error(), true), nil)
			return
		}
		defer os.Remove(profilePath)

		execPath, err := exec.LookPath(sandboxExecBinary)
		if err != nil {
			yield(errorEvent(executionID, "SANDBOX_EXEC_MISSING", "sandbox-exec binary not found", true), nil)
			return
		}

		execCtx, cancel := withTimeout(ctx, req, cfg)
		if cancel != nil {
			defer cancel()
		}

		args := append([]string{"-f", profilePath, "--"}, req.GetCommand()...)
		cmd := exec.CommandContext(execCtx, execPath, args...)

		if req.GetWorkDir() != "" {
			cmd.Dir = req.GetWorkDir()
		} else if req.GetWorkspaceDir() != "" {
			cmd.Dir = req.GetWorkspaceDir()
		}

		env, _ := filteredEnvironment(req.GetEnv())
		cmd.Env = env

		if len(req.GetStdin()) > 0 {
			cmd.Stdin = bytes.NewReader(req.GetStdin())
		}

		stdoutPipe, err := cmd.StdoutPipe()
		if err != nil {
			yield(errorEvent(executionID, "EXEC_SETUP_FAILED", fmt.Sprintf("stdout pipe failed: %v", err), true), nil)
			return
		}
		stderrPipe, err := cmd.StderrPipe()
		if err != nil {
			yield(errorEvent(executionID, "EXEC_SETUP_FAILED", fmt.Sprintf("stderr pipe failed: %v", err), true), nil)
			return
		}

		if err := cmd.Start(); err != nil {
			yield(errorEvent(executionID, "EXEC_START_FAILED", fmt.Sprintf("execution failed: %v", err), true), nil)
			return
		}

		if !yield(&sandboxv1.ExecuteEvent{
			ExecutionId: executionID,
			Timestamp:   timestamppb.Now(),
			Details: &sandboxv1.ExecuteEvent_Started{
				Started: &sandboxv1.StartedEvent{
					ExecutionId:     executionID,
					Runtime:         sandboxv1.Runtime_RUNTIME_SANDBOX_EXEC,
					EffectiveConfig: cfg,
				},
			},
		}, nil) {
			_ = cmd.Process.Kill()
			return
		}

		if !yield(errorEvent(executionID, "DEPRECATED_RUNTIME", "sandbox-exec is deprecated on macOS; use containers when possible", false), nil) {
			_ = cmd.Process.Kill()
			return
		}

		outputCh := make(chan *sandboxv1.ExecuteEvent, 100)
		var wg sync.WaitGroup
		wg.Add(2)
		go streamPipe(&wg, stdoutPipe, false, executionID, outputCh)
		go streamPipe(&wg, stderrPipe, true, executionID, outputCh)
		go func() {
			wg.Wait()
			close(outputCh)
		}()

		waitCh := make(chan error, 1)
		go func() {
			waitCh <- cmd.Wait()
		}()

		var waitErr error
		for outputCh != nil || waitCh != nil {
			select {
			case event, ok := <-outputCh:
				if !ok {
					outputCh = nil
					continue
				}
				if !yield(event, nil) {
					_ = cmd.Process.Kill()
					return
				}
			case err := <-waitCh:
				waitErr = err
				waitCh = nil
			}
		}

		exitCode := int32(0)
		if waitErr != nil {
			if exitErr, ok := waitErr.(*exec.ExitError); ok {
				exitCode = int32(exitErr.ExitCode())
			} else {
				yield(errorEvent(executionID, "EXEC_FAILED", fmt.Sprintf("execution failed: %v", waitErr), true), nil)
				return
			}
		}

		duration := time.Since(startTime)
		yield(&sandboxv1.ExecuteEvent{
			ExecutionId: executionID,
			Timestamp:   timestamppb.Now(),
			Details: &sandboxv1.ExecuteEvent_Completed{
				Completed: &sandboxv1.CompletedEvent{
					ExitCode: exitCode,
					Duration: durationpb.New(duration),
				},
			},
		}, nil)
	}
}

// Cleanup is a no-op for sandbox-exec.
func (r *Runtime) Cleanup(ctx context.Context, executionID string) error {
	return nil
}

func supportedModes() []sandboxv1.Mode {
	return []sandboxv1.Mode{
		sandboxv1.Mode_MODE_READ_ONLY,
		sandboxv1.Mode_MODE_WORKSPACE_WRITE,
		sandboxv1.Mode_MODE_NETWORK_ISOLATED,
		sandboxv1.Mode_MODE_EPHEMERAL,
		sandboxv1.Mode_MODE_FULL_ACCESS,
	}
}

func validateConfig(cfg *sandboxv1.SandboxConfig) error {
	if cfg.GetNetworkMode() == sandboxv1.NetworkMode_NETWORK_MODE_ALLOWLIST {
		return fmt.Errorf("network allowlist is not supported by sandbox-exec")
	}
	if len(cfg.GetNetworkAllowlist()) > 0 {
		return fmt.Errorf("network allowlist is not supported by sandbox-exec")
	}
	if len(cfg.GetMounts()) > 0 {
		return fmt.Errorf("additional mounts are not supported by sandbox-exec")
	}
	if len(cfg.GetReadOnlyPaths()) > 0 {
		return fmt.Errorf("read-only paths are not supported by sandbox-exec")
	}
	if len(cfg.GetHiddenPaths()) > 0 {
		return fmt.Errorf("hidden paths are not supported by sandbox-exec")
	}
	if cfg.GetSeccompProfile() != "" {
		return fmt.Errorf("seccomp profiles are not supported by sandbox-exec")
	}
	if cfg.GetUser() != "" || cfg.GetGroup() != "" {
		return fmt.Errorf("user/group overrides are not supported by sandbox-exec")
	}
	if len(cfg.GetDropCapabilities()) > 0 || len(cfg.GetAddCapabilities()) > 0 {
		return fmt.Errorf("capability configuration is not supported by sandbox-exec")
	}
	if len(cfg.GetExtraOptions()) > 0 {
		return fmt.Errorf("extra options are not supported by sandbox-exec")
	}
	return nil
}

func buildProfile(cfg *sandboxv1.SandboxConfig, workspaceDir string) (string, error) {
	mode := cfg.GetMode()
	if mode == sandboxv1.Mode_MODE_UNSPECIFIED {
		mode = sandboxv1.Mode_MODE_WORKSPACE_WRITE
	}

	workspaceDir, err := normalizePath(workspaceDir)
	if err != nil {
		return "", err
	}

	readSpecs := subpathSpecs(defaultReadPaths)
	execSpecs := subpathSpecs(defaultExecPaths)
	var writeSpecs []pathSpec

	// Expand profiles to read/exec/write paths
	profilePaths := expandProfiles(cfg.GetProfiles())
	if len(profilePaths.Read) > 0 {
		resolved, _ := resolvePaths(profilePaths.Read)
		readSpecs = append(readSpecs, subpathSpecs(resolved)...)
	}
	if len(profilePaths.Exec) > 0 {
		resolved, _ := resolvePaths(profilePaths.Exec)
		execSpecs = append(execSpecs, subpathSpecs(resolved)...)
	}
	if len(profilePaths.Write) > 0 {
		resolved, _ := resolvePaths(profilePaths.Write)
		writeSpecs = append(writeSpecs, subpathSpecs(resolved)...)
	}

	// Add explicit read_paths from config
	if paths := cfg.GetReadPaths(); len(paths) > 0 {
		resolved, _ := resolvePaths(paths)
		readSpecs = append(readSpecs, subpathSpecs(resolved)...)
	}

	// Add explicit exec_paths from config
	if paths := cfg.GetExecPaths(); len(paths) > 0 {
		resolved, _ := resolvePaths(paths)
		execSpecs = append(execSpecs, subpathSpecs(resolved)...)
	}

	// Add explicit write_paths from config
	if paths := cfg.GetWritePaths(); len(paths) > 0 {
		resolved, _ := resolvePaths(paths)
		writeSpecs = append(writeSpecs, subpathSpecs(resolved)...)
	}

	if workspaceDir != "" {
		readSpecs = append(readSpecs, pathSpec{Path: workspaceDir})
		execSpecs = append(execSpecs, pathSpec{Path: workspaceDir})
	}

	execAllowlist, err := resolveExecAllowlist(cfg.GetExecAllowlist(), workspaceDir)
	if err != nil {
		return "", err
	}
	if len(execAllowlist) > 0 {
		readSpecs = append(readSpecs, execAllowlist...)
		execSpecs = append(execSpecs, execAllowlist...)
	}

	lines := []string{
		"(version 1)",
		"(deny default)",
		"(import \"system.sb\")",
		"(allow file-read-metadata)",
		"(allow process-fork)",
	}

	if allowNetwork(cfg.GetNetworkMode()) {
		lines = append(lines, "(allow network*)")
	}

	if line := allowPaths("process-exec*", execSpecs); line != "" {
		lines = append(lines, line)
	}
	if line := allowPaths("file-map-executable", execSpecs); line != "" {
		lines = append(lines, line)
	}
	if line := allowPaths("file-read* file-test-existence", readSpecs); line != "" {
		lines = append(lines, line)
	}

	switch mode {
	case sandboxv1.Mode_MODE_FULL_ACCESS:
		lines = append(lines, allowPaths("file-read* file-write* file-test-existence", []pathSpec{{Path: "/"}}))
		lines = append(lines, allowPaths("file-map-executable", []pathSpec{{Path: "/"}}))
		lines = append(lines, allowPaths("process-exec*", []pathSpec{{Path: "/"}}))
		// Allow Mach IPC for system services (needed by apps using SystemConfiguration, etc.)
		lines = append(lines, "(allow mach*)")
	case sandboxv1.Mode_MODE_EPHEMERAL:
		lines = append(lines, allowPaths("file-write*", subpathSpecs(tempPaths())))
	case sandboxv1.Mode_MODE_WORKSPACE_WRITE, sandboxv1.Mode_MODE_NETWORK_ISOLATED:
		writePathSpecs := writeSpecs // Start with profile/config write paths
		if workspaceDir != "" {
			writePathSpecs = append(writePathSpecs, pathSpec{Path: workspaceDir})
		}
		writePathSpecs = append(writePathSpecs, subpathSpecs(tempPaths())...)
		lines = append(lines, allowPaths("file-write*", writePathSpecs))
	case sandboxv1.Mode_MODE_READ_ONLY:
	default:
	}

	return strings.Join(compact(lines), "\n") + "\n", nil
}

func allowNetwork(mode sandboxv1.NetworkMode) bool {
	switch mode {
	case sandboxv1.NetworkMode_NETWORK_MODE_HOST, sandboxv1.NetworkMode_NETWORK_MODE_BRIDGE:
		return true
	default:
		return false
	}
}

func tempPaths() []string {
	paths := []string{}

	// Add os.TempDir() with symlinks resolved
	if tmpDir := os.TempDir(); tmpDir != "" {
		if resolved, err := filepath.EvalSymlinks(tmpDir); err == nil {
			paths = append(paths, resolved)
		} else {
			paths = append(paths, tmpDir)
		}
	}

	// Add common temp paths with symlinks resolved
	// On macOS: /tmp -> /private/tmp, /var/tmp -> /private/var/tmp
	for _, p := range []string{"/tmp", "/var/tmp"} {
		if resolved, err := filepath.EvalSymlinks(p); err == nil {
			paths = append(paths, resolved)
		} else {
			paths = append(paths, p)
		}
	}

	return uniquePaths(paths)
}

// ProfilePaths holds paths expanded from a profile.
type ProfilePaths struct {
	Read  []string
	Exec  []string
	Write []string
}

// builtinProfiles defines the built-in sandbox profiles.
// Users can request these via --profile flag. Each profile expands to
// read/exec/write paths appropriate for that use case.
//
// Paths use ~ for home directory, which is expanded at runtime.
var builtinProfiles = map[string]ProfilePaths{
	// Git operations: read gitconfig and SSH keys
	"git": {
		Read: []string{
			"~/.gitconfig",
			"~/.config/git",
			"~/.ssh",
		},
	},
	// Node.js/npm development
	"node": {
		Read: []string{
			"~/.npm",
			"~/.npmrc",
			"~/.nvm",
			"~/.config/npm",
		},
		Write: []string{
			"~/.npm/_cacache", // npm cache
		},
	},
	// Go development
	"go": {
		Read: []string{
			"~/.go",
			"~/go",
			"~/.cache/go-build",
		},
		Exec: []string{
			"~/go/bin",
		},
		Write: []string{
			"~/.cache/go-build",
		},
	},
	// Python development
	"python": {
		Read: []string{
			"~/.pyenv",
			"~/.local/lib/python*",
			"~/.config/pip",
			"~/.pip",
		},
		Exec: []string{
			"~/.pyenv/shims",
			"~/.local/bin",
		},
	},
	// Rust development
	"rust": {
		Read: []string{
			"~/.cargo",
			"~/.rustup",
		},
		Exec: []string{
			"~/.cargo/bin",
			"~/.rustup/toolchains",
		},
	},
	// XDG base directories (common config/cache)
	"xdg": {
		Read: []string{
			"~/.config",
			"~/.local/share",
			"~/.cache",
		},
		Write: []string{
			"~/.cache",
		},
	},
	// OpenAI Codex CLI
	"codex": {
		Read: []string{
			"~/.codex",
			"~/.config/codex",
		},
	},
	// Claude Code / Anthropic tools
	"claude": {
		Read: []string{
			"~/.claude",
			"~/.config/claude",
			"~/.anthropic",
		},
	},
}

// AvailableProfiles returns the list of available built-in profile names.
func AvailableProfiles() []string {
	profiles := make([]string, 0, len(builtinProfiles))
	for name := range builtinProfiles {
		profiles = append(profiles, name)
	}
	return profiles
}

// ValidateProfiles checks if all profile names are valid.
// Returns an error listing any unknown profiles.
func ValidateProfiles(profiles []string) error {
	var unknown []string
	for _, name := range profiles {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			continue
		}
		if _, ok := builtinProfiles[name]; !ok {
			unknown = append(unknown, name)
		}
	}
	if len(unknown) > 0 {
		available := AvailableProfiles()
		return fmt.Errorf("unknown sandbox profile(s): %s (available: %s)",
			strings.Join(unknown, ", "),
			strings.Join(available, ", "))
	}
	return nil
}

// expandProfiles expands profile names to their path definitions.
// Unknown profiles are logged at warn level for security visibility.
func expandProfiles(profiles []string) ProfilePaths {
	result := ProfilePaths{}
	for _, name := range profiles {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			continue
		}
		if profile, ok := builtinProfiles[name]; ok {
			result.Read = append(result.Read, profile.Read...)
			result.Exec = append(result.Exec, profile.Exec...)
			result.Write = append(result.Write, profile.Write...)
		} else {
			// Warn rather than silently ignore - security visibility
			slog.Warn("unknown sandbox profile ignored",
				"profile", name,
				"available", AvailableProfiles(),
			)
		}
	}
	return result
}

// resolvePaths expands ~ to home directory and resolves symlinks.
// Returns resolved paths and any paths that couldn't be resolved (logged).
func resolvePaths(paths []string) ([]string, []string) {
	home, _ := os.UserHomeDir()
	var resolved, failed []string

	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}

		// Expand ~ to home directory
		if strings.HasPrefix(p, "~/") && home != "" {
			p = filepath.Join(home, p[2:])
		} else if p == "~" && home != "" {
			p = home
		}

		// Resolve to absolute path and handle symlinks
		abs, err := filepath.Abs(p)
		if err != nil {
			failed = append(failed, p)
			continue
		}

		// Try to resolve symlinks (but don't fail if path doesn't exist)
		if r, err := filepath.EvalSymlinks(abs); err == nil {
			resolved = append(resolved, r)
		} else {
			// Path might not exist yet, use the absolute path
			resolved = append(resolved, abs)
		}
	}

	return resolved, failed
}

func normalizePath(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", nil
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve path %q: %w", path, err)
	}
	// On macOS, /tmp -> /private/tmp and /var -> /private/var
	// We must resolve symlinks for the sandbox profile to work correctly
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		// If the path doesn't exist yet, try resolving the parent
		// This handles cases like creating new files in the workspace
		parent := filepath.Dir(abs)
		resolvedParent, parentErr := filepath.EvalSymlinks(parent)
		if parentErr != nil {
			// Fall back to cleaned absolute path if we can't resolve
			return filepath.Clean(abs), nil
		}
		return filepath.Join(resolvedParent, filepath.Base(abs)), nil
	}
	return resolved, nil
}

func resolveExecAllowlist(entries []string, workspaceDir string) ([]pathSpec, error) {
	if len(entries) == 0 {
		return nil, nil
	}

	specs := make([]pathSpec, 0, len(entries))
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			return nil, fmt.Errorf("exec allowlist entry is empty")
		}

		resolved, err := resolveAllowlistEntry(entry, workspaceDir)
		if err != nil {
			return nil, err
		}

		if err := sandbox.ValidatePath(resolved); err != nil {
			return nil, fmt.Errorf("exec allowlist entry %q: %w", entry, err)
		}

		info, err := os.Stat(resolved)
		if err != nil {
			return nil, fmt.Errorf("exec allowlist entry %q: %w", entry, err)
		}

		if info.IsDir() {
			specs = append(specs, pathSpec{Path: resolved})
		} else {
			specs = append(specs, pathSpec{Path: resolved, Literal: true})
		}
	}

	return specs, nil
}

func resolveAllowlistEntry(entry, workspaceDir string) (string, error) {
	if filepath.IsAbs(entry) {
		return resolveSymlinks(filepath.Clean(entry)), nil
	}

	if strings.ContainsRune(entry, os.PathSeparator) || strings.HasPrefix(entry, ".") {
		base := entry
		if workspaceDir != "" {
			base = filepath.Join(workspaceDir, entry)
		}
		resolved, err := filepath.Abs(base)
		if err != nil {
			return "", fmt.Errorf("resolve exec allowlist entry %q: %w", entry, err)
		}
		return resolveSymlinks(filepath.Clean(resolved)), nil
	}

	resolved, err := exec.LookPath(entry)
	if err != nil {
		return "", fmt.Errorf("exec allowlist command %q not found in PATH", entry)
	}
	return resolveSymlinks(filepath.Clean(resolved)), nil
}

func resolveSymlinks(path string) string {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return path
	}
	return resolved
}

func writeProfile(profile string) (string, error) {
	f, err := os.CreateTemp("", "deputy-sandbox-*.sb")
	if err != nil {
		return "", fmt.Errorf("create sandbox profile: %w", err)
	}
	path := f.Name()
	if _, err := f.WriteString(profile); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return "", fmt.Errorf("write sandbox profile: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("close sandbox profile: %w", err)
	}
	return path, nil
}

func allowPaths(ops string, specs []pathSpec) string {
	if len(specs) == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString("(allow ")
	b.WriteString(ops)

	seen := make(map[string]struct{}, len(specs))
	added := 0
	for _, spec := range specs {
		path := strings.TrimSpace(spec.Path)
		if path == "" {
			continue
		}

		key := fmt.Sprintf("%t:%s", spec.Literal, path)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		filter := "subpath"
		if spec.Literal {
			filter = "literal"
		}
		b.WriteString("\n  (")
		b.WriteString(filter)
		b.WriteString(" \"")
		b.WriteString(sbplEscape(path))
		b.WriteString("\")")
		added++
	}
	b.WriteString(")")
	if added == 0 {
		return ""
	}
	return b.String()
}

func sbplEscape(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	return strings.ReplaceAll(value, "\"", "\\\"")
}

func subpathSpecs(paths []string) []pathSpec {
	specs := make([]pathSpec, 0, len(paths))
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		specs = append(specs, pathSpec{Path: path})
	}
	return specs
}

func compact(lines []string) []string {
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		out = append(out, line)
	}
	return out
}

func uniquePaths(paths []string) []string {
	seen := make(map[string]struct{}, len(paths))
	out := make([]string, 0, len(paths))
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		out = append(out, path)
	}
	return out
}

func withTimeout(ctx context.Context, req *sandboxv1.ExecuteRequest, cfg *sandboxv1.SandboxConfig) (context.Context, context.CancelFunc) {
	timeout := time.Duration(0)
	if req.GetTimeout() != nil {
		timeout = req.GetTimeout().AsDuration()
	}
	if limits := cfg.GetLimits(); limits != nil && limits.GetMaxTime() != nil {
		limit := limits.GetMaxTime().AsDuration()
		if timeout == 0 || (limit > 0 && limit < timeout) {
			timeout = limit
		}
	}
	if timeout <= 0 {
		return ctx, nil
	}
	return context.WithTimeout(ctx, timeout)
}

func filteredEnvironment(extra map[string]string) ([]string, []string) {
	return sandbox.SanitizeEnvironment(os.Environ(), extra)
}

func streamPipe(wg *sync.WaitGroup, reader io.Reader, isStderr bool, executionID string, out chan<- *sandboxv1.ExecuteEvent) {
	defer wg.Done()

	buf := make([]byte, 4096)
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			data := make([]byte, n)
			copy(data, buf[:n])
			out <- &sandboxv1.ExecuteEvent{
				ExecutionId: executionID,
				Timestamp:   timestamppb.Now(),
				Details: &sandboxv1.ExecuteEvent_Output{
					Output: &sandboxv1.OutputEvent{
						IsStderr: isStderr,
						Data:     data,
					},
				},
			}
		}
		if err != nil {
			if err != io.EOF {
				out <- errorEvent(executionID, "STREAM_ERROR", fmt.Sprintf("output stream error: %v", err), false)
			}
			return
		}
	}
}

func errorEvent(executionID, code, message string, fatal bool) *sandboxv1.ExecuteEvent {
	return &sandboxv1.ExecuteEvent{
		ExecutionId: executionID,
		Timestamp:   timestamppb.Now(),
		Details: &sandboxv1.ExecuteEvent_Error{
			Error: &sandboxv1.ErrorEvent{
				Message: message,
				Code:    code,
				IsFatal: fatal,
			},
		},
	}
}
