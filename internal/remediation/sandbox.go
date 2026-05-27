// Package remediation provides vulnerability remediation planning and execution.
package remediation

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	sandboxv1 "github.com/temporalio/deputy/gen/deputy/sandbox/v1"
	"github.com/temporalio/deputy/internal/sandbox"
	"github.com/temporalio/deputy/internal/sandbox/runtimes/docker"
	"github.com/temporalio/deputy/internal/sandbox/runtimes/gvisor"
	"github.com/temporalio/deputy/internal/sandbox/runtimes/none"
	"github.com/temporalio/deputy/internal/sandbox/runtimes/plugin"
	"github.com/temporalio/deputy/internal/sandbox/runtimes/sandboxexec"
	"google.golang.org/protobuf/types/known/durationpb"
)

// SandboxConfig configures sandboxed remediation execution.
type SandboxConfig struct {
	// Enabled determines whether to use sandbox execution.
	// When false, commands execute directly via os/exec.
	Enabled bool

	// Runtime specifies the sandbox runtime to use.
	// Empty string uses the default (docker).
	Runtime string

	// PluginName is the plugin name when Runtime is "plugin".
	PluginName string

	// Image is the container image for container runtimes.
	// If empty, uses ecosystem-specific defaults.
	Image string

	// NetworkMode controls network access.
	// Valid values: "none", "allowlist", "bridge", "host".
	// Default is "allowlist" with ecosystem-appropriate endpoints.
	NetworkMode string

	// NetworkAllowlist specifies allowed network endpoints.
	// If empty and NetworkMode is "allowlist", uses ecosystem defaults.
	NetworkAllowlist []string

	// Mode controls filesystem access.
	// Default is "workspace-write".
	Mode string

	// Review pauses after execution to show changes before applying.
	Review bool

	// Timeout for each command execution.
	Timeout string

	// Verbose shows detailed sandbox output.
	Verbose bool
}

// EcosystemNetworkProfiles maps ecosystems to their required network endpoints.
// These are used when NetworkMode is "allowlist" and no explicit allowlist is provided.
var EcosystemNetworkProfiles = map[string][]string{
	"go": {
		"proxy.golang.org:443",
		"sum.golang.org:443",
		"storage.googleapis.com:443",
	},
	"npm": {
		"registry.npmjs.org:443",
		"registry.yarnpkg.com:443",
	},
	"yarn": {
		"registry.npmjs.org:443",
		"registry.yarnpkg.com:443",
	},
	"pnpm": {
		"registry.npmjs.org:443",
	},
	"pip": {
		"pypi.org:443",
		"files.pythonhosted.org:443",
	},
	"poetry": {
		"pypi.org:443",
		"files.pythonhosted.org:443",
	},
	"pipenv": {
		"pypi.org:443",
		"files.pythonhosted.org:443",
	},
	"uv": {
		"pypi.org:443",
		"files.pythonhosted.org:443",
	},
	"cargo": {
		"crates.io:443",
		"static.crates.io:443",
	},
	"gem": {
		"rubygems.org:443",
	},
	"bundler": {
		"rubygems.org:443",
	},
	"composer": {
		"packagist.org:443",
		"repo.packagist.org:443",
	},
	"maven": {
		"repo1.maven.org:443",
		"repo.maven.apache.org:443",
	},
	"gradle": {
		"repo1.maven.org:443",
		"services.gradle.org:443",
		"plugins.gradle.org:443",
	},
	"nuget": {
		"api.nuget.org:443",
	},
	"dotnet": {
		"api.nuget.org:443",
	},
	"hex": {
		"hex.pm:443",
	},
	"mix": {
		"hex.pm:443",
	},
	"pub": {
		"pub.dev:443",
	},
	"dart": {
		"pub.dev:443",
	},
	"cocoapods": {
		"cdn.cocoapods.org:443",
	},
	"conan": {
		"conan.io:443",
	},
}

// EcosystemImages maps ecosystems to recommended container images.
var EcosystemImages = map[string]string{
	"go":       "golang:1.23-alpine",
	"npm":      "node:22-alpine",
	"yarn":     "node:22-alpine",
	"pnpm":     "node:22-alpine",
	"pip":      "python:3.12-alpine",
	"poetry":   "python:3.12-alpine",
	"pipenv":   "python:3.12-alpine",
	"uv":       "ghcr.io/astral-sh/uv:python3.12-alpine",
	"cargo":    "rust:1.83-alpine",
	"gem":      "ruby:3.3-alpine",
	"bundler":  "ruby:3.3-alpine",
	"composer": "composer:2",
	"maven":    "maven:3-eclipse-temurin-21-alpine",
	"gradle":   "gradle:8-jdk21-alpine",
	"nuget":    "mcr.microsoft.com/dotnet/sdk:8.0-alpine",
	"dotnet":   "mcr.microsoft.com/dotnet/sdk:8.0-alpine",
}

// Executor handles sandboxed execution of remediation commands.
type Executor struct {
	config  SandboxConfig
	manager *sandbox.Manager
	out     io.Writer
	errW    io.Writer
}

// NewExecutor creates a new sandboxed executor.
func NewExecutor(ctx context.Context, config SandboxConfig, out, errW io.Writer) (*Executor, error) {
	if !config.Enabled {
		return &Executor{config: config, out: out, errW: errW}, nil
	}

	reg := sandbox.NewRegistry()
	reg.Register(none.New())
	reg.Register(docker.New())
	reg.Register(gvisor.New())
	reg.Register(sandboxexec.New())

	pluginRuntime := plugin.New()
	reg.Register(pluginRuntime)

	mgr, err := sandbox.NewManager(ctx, sandbox.WithRegistry(reg))
	if err != nil {
		return nil, fmt.Errorf("create sandbox manager: %w", err)
	}

	return &Executor{
		config:  config,
		manager: mgr,
		out:     out,
		errW:    errW,
	}, nil
}

// Close releases executor resources.
func (e *Executor) Close() error {
	if e.manager != nil {
		return e.manager.Close()
	}
	return nil
}

// Execute runs a remediation command, optionally in a sandbox.
func (e *Executor) Execute(ctx context.Context, repoDir string, cmd Command) error {
	if !e.config.Enabled {
		return e.executeDirect(ctx, repoDir, cmd)
	}
	return e.executeSandboxed(ctx, repoDir, cmd)
}

// executeDirect runs the command without sandboxing (existing behavior).
func (e *Executor) executeDirect(ctx context.Context, repoDir string, cmd Command) error {
	// This path is handled by the existing applyRemediationCommands in fix.go
	// We just return nil here to indicate the executor doesn't handle unsandboxed execution
	return fmt.Errorf("direct execution not implemented in Executor; use applyRemediationCommands")
}

// executeSandboxed runs the command in a sandbox.
func (e *Executor) executeSandboxed(ctx context.Context, repoDir string, cmd Command) error {
	args, err := ExecArgs(cmd)
	if err != nil {
		return fmt.Errorf("parse command: %w", err)
	}

	// Determine working directory
	workDir := repoDir
	if strings.TrimSpace(cmd.Path) != "" {
		relDir := filepath.Dir(cmd.Path)
		if relDir != "." && relDir != "" {
			workDir = filepath.Join(repoDir, relDir)
		}
	}

	// Build sandbox request
	req, err := e.buildRequest(args, repoDir, workDir, cmd.Manager)
	if err != nil {
		return fmt.Errorf("build sandbox request: %w", err)
	}

	// Execute in sandbox
	var exitCode int32
	var execErr error

	for event, err := range e.manager.Execute(ctx, req) {
		if err != nil {
			return fmt.Errorf("sandbox execution error: %w", err)
		}
		if event == nil {
			continue
		}

		switch details := event.GetDetails().(type) {
		case *sandboxv1.ExecuteEvent_Output:
			if details.Output.GetIsStderr() {
				if e.errW != nil {
					_, _ = e.errW.Write(details.Output.GetData())
				}
			} else if e.out != nil {
				_, _ = e.out.Write(details.Output.GetData())
			}
		case *sandboxv1.ExecuteEvent_Error:
			if details.Error.GetIsFatal() {
				execErr = fmt.Errorf("%s: %s", details.Error.GetCode(), details.Error.GetMessage())
			} else if e.config.Verbose && e.errW != nil {
				fmt.Fprintln(e.errW, details.Error.GetMessage())
			}
		case *sandboxv1.ExecuteEvent_Completed:
			exitCode = details.Completed.GetExitCode()
		}

		if execErr != nil {
			break
		}
	}

	if execErr != nil {
		return execErr
	}
	if exitCode != 0 {
		return fmt.Errorf("command exited with code %d", exitCode)
	}

	// Execute follow-up command if present
	if cmd.FollowUp != "" && len(cmd.FollowUpArgs) > 0 {
		followUpReq, err := e.buildRequest(cmd.FollowUpArgs, repoDir, workDir, cmd.Manager)
		if err != nil {
			return fmt.Errorf("build follow-up request: %w", err)
		}

		for event, err := range e.manager.Execute(ctx, followUpReq) {
			if err != nil {
				return fmt.Errorf("follow-up execution error: %w", err)
			}
			if event == nil {
				continue
			}

			switch details := event.GetDetails().(type) {
			case *sandboxv1.ExecuteEvent_Output:
				if details.Output.GetIsStderr() {
					if e.errW != nil {
						_, _ = e.errW.Write(details.Output.GetData())
					}
				} else if e.out != nil {
					_, _ = e.out.Write(details.Output.GetData())
				}
			case *sandboxv1.ExecuteEvent_Error:
				if details.Error.GetIsFatal() {
					execErr = fmt.Errorf("%s: %s", details.Error.GetCode(), details.Error.GetMessage())
				}
			case *sandboxv1.ExecuteEvent_Completed:
				exitCode = details.Completed.GetExitCode()
			}

			if execErr != nil {
				break
			}
		}

		if execErr != nil {
			return fmt.Errorf("follow-up command failed: %w", execErr)
		}
		if exitCode != 0 {
			return fmt.Errorf("follow-up command exited with code %d", exitCode)
		}
	}

	return nil
}

// buildRequest constructs a sandbox execution request for a remediation command.
func (e *Executor) buildRequest(args []string, workspaceDir, workDir, manager string) (*sandboxv1.ExecuteRequest, error) {
	runtime, err := parseRuntime(e.config.Runtime)
	if err != nil {
		return nil, err
	}

	mode, err := parseMode(e.config.Mode)
	if err != nil {
		return nil, err
	}

	networkMode, err := parseNetworkMode(e.config.NetworkMode)
	if err != nil {
		return nil, err
	}

	// Build network allowlist
	var allowlist []string
	if networkMode == sandboxv1.NetworkMode_NETWORK_MODE_ALLOWLIST {
		if len(e.config.NetworkAllowlist) > 0 {
			allowlist = e.config.NetworkAllowlist
		} else {
			// Use ecosystem defaults
			allowlist = EcosystemNetworkProfiles[strings.ToLower(manager)]
		}
	}

	// Select image
	image := e.config.Image
	if image == "" {
		image = EcosystemImages[strings.ToLower(manager)]
	}
	if image == "" {
		image = "alpine:latest"
	}

	config := &sandboxv1.SandboxConfig{
		Runtime:          runtime,
		Mode:             mode,
		NetworkMode:      networkMode,
		Image:            image,
		NetworkAllowlist: allowlist,
		PluginName:       e.config.PluginName,
	}

	req := &sandboxv1.ExecuteRequest{
		Command:      args,
		Config:       config,
		WorkDir:      workDir,
		WorkspaceDir: workspaceDir,
		Context: &sandboxv1.ExecutionContext{
			Source: sandboxv1.ExecutionSource_EXECUTION_SOURCE_REMEDIATION,
		},
	}

	if e.config.Timeout != "" {
		timeout, err := parseDuration(e.config.Timeout)
		if err != nil {
			return nil, fmt.Errorf("invalid timeout: %w", err)
		}
		req.Timeout = timeout
	}

	return req, nil
}

func parseRuntime(s string) (sandboxv1.Runtime, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "docker":
		return sandboxv1.Runtime_RUNTIME_DOCKER, nil
	case "gvisor":
		return sandboxv1.Runtime_RUNTIME_GVISOR, nil
	case "none":
		return sandboxv1.Runtime_RUNTIME_NONE, nil
	case "sandbox-exec", "sandboxexec":
		return sandboxv1.Runtime_RUNTIME_SANDBOX_EXEC, nil
	case "plugin":
		return sandboxv1.Runtime_RUNTIME_PLUGIN, nil
	default:
		return sandboxv1.Runtime_RUNTIME_UNSPECIFIED, fmt.Errorf("unsupported runtime: %s", s)
	}
}

func parseMode(s string) (sandboxv1.Mode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "workspace-write", "rw":
		return sandboxv1.Mode_MODE_WORKSPACE_WRITE, nil
	case "read-only", "ro":
		return sandboxv1.Mode_MODE_READ_ONLY, nil
	case "full-access":
		return sandboxv1.Mode_MODE_FULL_ACCESS, nil
	case "ephemeral":
		return sandboxv1.Mode_MODE_EPHEMERAL, nil
	default:
		return sandboxv1.Mode_MODE_UNSPECIFIED, fmt.Errorf("unsupported mode: %s", s)
	}
}

func parseNetworkMode(s string) (sandboxv1.NetworkMode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "allowlist":
		return sandboxv1.NetworkMode_NETWORK_MODE_ALLOWLIST, nil
	case "none":
		return sandboxv1.NetworkMode_NETWORK_MODE_NONE, nil
	case "bridge":
		return sandboxv1.NetworkMode_NETWORK_MODE_BRIDGE, nil
	case "host":
		return sandboxv1.NetworkMode_NETWORK_MODE_HOST, nil
	default:
		return sandboxv1.NetworkMode_NETWORK_MODE_UNSPECIFIED, fmt.Errorf("unsupported network mode: %s", s)
	}
}

func parseDuration(s string) (*durationpb.Duration, error) {
	d, err := time.ParseDuration(s)
	if err != nil {
		return nil, err
	}
	return durationpb.New(d), nil
}
