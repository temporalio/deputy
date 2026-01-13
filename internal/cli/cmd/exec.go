package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	sandboxv1 "github.com/picatz/deputy/gen/deputy/sandbox/v1"
	deputyerrors "github.com/picatz/deputy/internal/errors"
	"github.com/picatz/deputy/internal/policy"
	"github.com/picatz/deputy/internal/sandbox"
	"github.com/picatz/deputy/internal/sandbox/runtimes/docker"
	"github.com/picatz/deputy/internal/sandbox/runtimes/gvisor"
	"github.com/picatz/deputy/internal/sandbox/runtimes/landlock"
	"github.com/picatz/deputy/internal/sandbox/runtimes/none"
	"github.com/picatz/deputy/internal/sandbox/runtimes/plugin"
	"github.com/picatz/deputy/internal/sandbox/runtimes/sandboxexec"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/durationpb"
)

type execFlags struct {
	runtime               string
	mode                  string
	network               string
	networkAllow          []string
	image                 string
	workspace             string
	noWorkspace           bool
	workDir               string
	env                   []string
	stdinPath             string
	timeout               time.Duration
	pluginName            string
	memoryLimit           string
	cpuLimit              string
	maxPids               int32
	maxFiles              int32
	diskQuotaBytes        int64
	policyPaths           []string
	verbose               bool
	execAllow             []string
	dangerouslySkipPrompt bool
}

// AddExecCommand adds the exec command to the root command.
func AddExecCommand(root *cobra.Command, deps Dependencies) {
	flags := &execFlags{}

	cmd := &cobra.Command{
		Use:   "exec -- <command> [args...]",
		Short: "Run a command in a sandbox",
		Long: `Execute a command inside a sandboxed runtime.

By default, the current working directory is mounted as the workspace and
network access is disabled for safety.`,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return errors.New("provide the command to execute after --")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return runExec(cmd.Context(), deps, flags, args, cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}

	cmd.Flags().StringVar(&flags.runtime, "runtime", "docker", "Sandbox runtime (docker|gvisor|landlock|none|sandbox-exec|plugin)")
	cmd.Flags().StringVar(&flags.mode, "mode", "workspace-write", "Filesystem mode (read-only|workspace-write|full-access|network-isolated|ephemeral)")
	cmd.Flags().StringVar(&flags.network, "network", "none", "Network mode (none|host|bridge|allowlist)")
	cmd.Flags().StringArrayVar(&flags.networkAllow, "network-allow", nil, "Allowed hosts for network allowlist mode (repeatable)")
	cmd.Flags().StringVar(&flags.image, "image", "", "Container image for container runtimes")
	cmd.Flags().StringVar(&flags.workspace, "workspace", ".", "Workspace directory to mount into the sandbox")
	cmd.Flags().BoolVar(&flags.noWorkspace, "no-workspace", false, "Disable workspace mounting")
	cmd.Flags().StringVar(&flags.workDir, "work-dir", "", "Working directory inside the sandbox")
	cmd.Flags().StringArrayVar(&flags.env, "env", nil, "Environment variable (KEY=VALUE, repeatable)")
	cmd.Flags().StringVar(&flags.stdinPath, "stdin", "", "Stdin source file path or '-' for stdin")
	cmd.Flags().DurationVar(&flags.timeout, "timeout", 0, "Execution timeout (e.g., 30s, 5m)")
	cmd.Flags().StringVar(&flags.pluginName, "plugin", "", "Plugin name for plugin runtime")
	cmd.Flags().StringVar(&flags.memoryLimit, "memory", "", "Memory limit (e.g., 512m, 2g)")
	cmd.Flags().StringVar(&flags.cpuLimit, "cpu", "", "CPU limit (e.g., 1.0, 0.5)")
	cmd.Flags().Int32Var(&flags.maxPids, "max-pids", 0, "Maximum number of processes")
	cmd.Flags().Int32Var(&flags.maxFiles, "max-files", 0, "Maximum number of open files")
	cmd.Flags().Int64Var(&flags.diskQuotaBytes, "disk-quota", 0, "Disk quota in bytes")
	cmd.Flags().StringArrayVar(&flags.policyPaths, "policy", nil, "Policy file or bundle to enforce (repeatable)")
	cmd.Flags().BoolVar(&flags.verbose, "verbose", false, "Show non-fatal sandbox warnings")
	cmd.Flags().StringArrayVar(&flags.execAllow, "exec-allow", nil, "Allow additional executables by path or command name (repeatable)")
	cmd.Flags().BoolVar(&flags.dangerouslySkipPrompt, "dangerously-skip-prompt", false, "Skip confirmation prompt for dangerous modes (full-access, host network)")

	cmd.Example = strings.Join([]string{
		"deputy exec --mode read-only -- ls -la",
		"deputy exec --runtime docker --image alpine:3.19 -- echo hello",
		"deputy exec --runtime sandbox-exec --mode read-only -- ls -la",
		"deputy exec --runtime sandbox-exec --mode read-only --exec-allow deputy -- deputy list",
		"deputy exec --network allowlist --network-allow proxy.golang.org:443 -- go env GOPATH",
	}, "\n")
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true

	root.AddCommand(cmd)
}

func runExec(ctx context.Context, deps Dependencies, flags *execFlags, command []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if deps.ServerAddress != "" || os.Getenv("DEPUTY_SERVER") != "" {
		return fmt.Errorf("exec is only available in local mode; unset DEPUTY_SERVER to run locally")
	}

	runtimeType, err := parseSandboxRuntime(flags.runtime)
	if err != nil {
		return err
	}
	if runtimeType == sandboxv1.Runtime_RUNTIME_PLUGIN && strings.TrimSpace(flags.pluginName) == "" {
		return fmt.Errorf("--plugin is required when --runtime=plugin")
	}
	mode, err := parseExecSandboxMode(flags.mode)
	if err != nil {
		return err
	}
	networkMode, err := parseSandboxNetwork(flags.network)
	if err != nil {
		return err
	}
	envVars, err := parseEnvVars(flags.env)
	if err != nil {
		return err
	}
	stdinBytes, err := readStdinSource(flags.stdinPath, stdin)
	if err != nil {
		return err
	}

	var workspaceDir string
	if !flags.noWorkspace {
		workspaceDir, err = filepath.Abs(flags.workspace)
		if err != nil {
			return fmt.Errorf("resolve workspace path: %w", err)
		}
	}

	// Check if confirmation is required for dangerous modes or commands
	if !flags.dangerouslySkipPrompt && execConfirmationRequired(mode, networkMode, command) {
		info := execConfirmationInfo{
			Mode:        mode,
			NetworkMode: networkMode,
			Command:     command,
			Workspace:   workspaceDir,
		}
		if !confirmExecDangerousMode(info, stdin, stdout, stderr) {
			return fmt.Errorf("operation cancelled")
		}
	}

	var limits *sandboxv1.ResourceLimits
	if flags.memoryLimit != "" || flags.cpuLimit != "" || flags.maxPids > 0 || flags.maxFiles > 0 || flags.diskQuotaBytes > 0 {
		limits = &sandboxv1.ResourceLimits{
			Memory:    flags.memoryLimit,
			Cpu:       flags.cpuLimit,
			MaxPids:   flags.maxPids,
			MaxFiles:  flags.maxFiles,
			DiskQuota: flags.diskQuotaBytes,
		}
	}

	config := &sandboxv1.SandboxConfig{
		Runtime:          runtimeType,
		Mode:             mode,
		NetworkMode:      networkMode,
		Image:            strings.TrimSpace(flags.image),
		Limits:           limits,
		NetworkAllowlist: flags.networkAllow,
		PluginName:       strings.TrimSpace(flags.pluginName),
		ExecAllowlist:    flags.execAllow,
	}

	req := &sandboxv1.ExecuteRequest{
		Command:      command,
		Config:       config,
		WorkDir:      strings.TrimSpace(flags.workDir),
		Env:          envVars,
		Stdin:        stdinBytes,
		WorkspaceDir: workspaceDir,
		Context: &sandboxv1.ExecutionContext{
			Source:         sandboxv1.ExecutionSource_EXECUTION_SOURCE_EXEC,
			WrappedCommand: strings.Join(command, " "),
		},
	}

	if flags.timeout > 0 {
		req.Timeout = durationpb.New(flags.timeout)
	}

	var engine *policy.Engine
	if len(flags.policyPaths) > 0 {
		engine, err = policy.NewEngineFromPaths(flags.policyPaths)
		if err != nil {
			return err
		}
	}

	reg := sandbox.NewRegistry()
	reg.Register(none.New())
	reg.Register(docker.New())
	reg.Register(gvisor.New())
	reg.Register(sandboxexec.New())
	reg.Register(landlock.New())
	pluginRuntime := plugin.New()
	reg.Register(pluginRuntime)
	defer pluginRuntime.Close()

	mgr, err := sandbox.NewManager(ctx, sandbox.WithRegistry(reg), sandbox.WithPolicyEngine(engine))
	if err != nil {
		return err
	}

	var exitCode int32
	var execErr error

	for event, err := range mgr.Execute(ctx, req) {
		if err != nil {
			return err
		}
		if event == nil {
			continue
		}

		switch details := event.GetDetails().(type) {
		case *sandboxv1.ExecuteEvent_Output:
			if details.Output.GetIsStderr() {
				if stderr != nil {
					_, _ = stderr.Write(details.Output.GetData())
				}
			} else if stdout != nil {
				_, _ = stdout.Write(details.Output.GetData())
			}
		case *sandboxv1.ExecuteEvent_Error:
			message := strings.TrimSpace(details.Error.GetMessage())
			if message == "" {
				message = "sandbox execution failed"
			}
			if details.Error.GetIsFatal() {
				execErr = fmt.Errorf("%s", message)
				break
			}
			if details.Error.GetCode() == "DEPRECATED_RUNTIME" && !flags.verbose {
				break
			}
			if stderr != nil {
				fmt.Fprintln(stderr, message)
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
		return deputyerrors.WithExitCode(nil, int(exitCode))
	}
	return nil
}

func parseSandboxRuntime(value string) (sandboxv1.Runtime, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "docker":
		return sandboxv1.Runtime_RUNTIME_DOCKER, nil
	case "gvisor":
		return sandboxv1.Runtime_RUNTIME_GVISOR, nil
	case "none":
		return sandboxv1.Runtime_RUNTIME_NONE, nil
	case "sandbox-exec", "sandboxexec", "seatbelt", "macos":
		return sandboxv1.Runtime_RUNTIME_SANDBOX_EXEC, nil
	case "plugin":
		return sandboxv1.Runtime_RUNTIME_PLUGIN, nil
	case "landlock":
		return sandboxv1.Runtime_RUNTIME_LANDLOCK, nil
	default:
		return sandboxv1.Runtime_RUNTIME_UNSPECIFIED, fmt.Errorf("unsupported runtime %q (use docker|gvisor|none|sandbox-exec|landlock|plugin)", value)
	}
}

func parseExecSandboxMode(value string) (sandboxv1.Mode, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "workspace-write", "workspace", "rw":
		return sandboxv1.Mode_MODE_WORKSPACE_WRITE, nil
	case "read-only", "readonly", "ro":
		return sandboxv1.Mode_MODE_READ_ONLY, nil
	case "full-access", "danger-full-access", "full":
		return sandboxv1.Mode_MODE_FULL_ACCESS, nil
	case "network-isolated", "net-isolated":
		return sandboxv1.Mode_MODE_NETWORK_ISOLATED, nil
	case "ephemeral":
		return sandboxv1.Mode_MODE_EPHEMERAL, nil
	default:
		return sandboxv1.Mode_MODE_UNSPECIFIED, fmt.Errorf("unsupported mode %q", value)
	}
}

func parseSandboxNetwork(value string) (sandboxv1.NetworkMode, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "none":
		return sandboxv1.NetworkMode_NETWORK_MODE_NONE, nil
	case "host":
		return sandboxv1.NetworkMode_NETWORK_MODE_HOST, nil
	case "bridge":
		return sandboxv1.NetworkMode_NETWORK_MODE_BRIDGE, nil
	case "allowlist":
		return sandboxv1.NetworkMode_NETWORK_MODE_ALLOWLIST, nil
	default:
		return sandboxv1.NetworkMode_NETWORK_MODE_UNSPECIFIED, fmt.Errorf("unsupported network mode %q", value)
	}
}

func parseEnvVars(values []string) (map[string]string, error) {
	if len(values) == 0 {
		return nil, nil
	}

	env := make(map[string]string, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			continue
		}
		parts := strings.SplitN(value, "=", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" {
			return nil, fmt.Errorf("invalid env %q (expected KEY=VALUE)", value)
		}
		env[parts[0]] = parts[1]
	}
	return env, nil
}

func readStdinSource(path string, stdin io.Reader) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	if path == "-" {
		return io.ReadAll(stdin)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read stdin file %q: %w", path, err)
	}
	return data, nil
}
