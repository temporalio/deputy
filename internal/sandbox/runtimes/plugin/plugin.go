// Copyright 2024 Deputy Authors
// SPDX-License-Identifier: Apache-2.0

// Package plugin provides an external sandbox runtime implemented by plugins.
//
// Plugins are executables named deputy-sandbox-<name> discovered via PATH.
// Each plugin is launched with a Unix socket path using --socket and must serve
// the SandboxRuntimeService ConnectRPC interface on that socket.
package plugin

import (
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	sandboxv1 "github.com/picatz/deputy/gen/deputy/sandbox/v1"
	"github.com/picatz/deputy/gen/deputy/sandbox/v1/sandboxv1connect"
	"github.com/picatz/deputy/internal/sandbox"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	// PluginPrefix is the executable name prefix for sandbox runtime plugins.
	PluginPrefix = "deputy-sandbox-"

	socketWaitTimeout = 10 * time.Second
)

// Runtime implements sandbox.Runtime using external plugin executables.
type Runtime struct {
	logger *slog.Logger

	mu      sync.RWMutex
	plugins map[string]*pluginClient
}

type pluginClient struct {
	name       string
	execPath   string
	socketDir  string
	socketPath string
	cmd        *exec.Cmd
	client     sandboxv1connect.SandboxRuntimeServiceClient
	info       *sandboxv1.GetRuntimeInfoResponse
}

// Option configures the plugin runtime.
type Option func(*Runtime)

// WithLogger sets the logger used by the plugin runtime.
func WithLogger(logger *slog.Logger) Option {
	return func(r *Runtime) {
		if logger != nil {
			r.logger = logger
		}
	}
}

// New creates a new plugin runtime.
func New(opts ...Option) *Runtime {
	r := &Runtime{
		logger:  slog.Default(),
		plugins: make(map[string]*pluginClient),
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Ensure Runtime implements sandbox.Runtime.
var _ sandbox.Runtime = (*Runtime)(nil)

// Name returns RUNTIME_PLUGIN.
func (r *Runtime) Name() sandboxv1.Runtime {
	return sandboxv1.Runtime_RUNTIME_PLUGIN
}

// Info returns summary metadata for plugin runtimes.
func (r *Runtime) Info(ctx context.Context) (*sandboxv1.RuntimeInfo, error) {
	infos, err := r.RuntimeInfos(ctx, false)
	if err != nil {
		return nil, err
	}
	if len(infos) == 0 {
		return &sandboxv1.RuntimeInfo{
			Runtime:           sandboxv1.Runtime_RUNTIME_PLUGIN,
			DisplayName:       "Plugin",
			Available:         false,
			UnavailableReason: "no sandbox plugins found in PATH",
		}, nil
	}
	return infos[0], nil
}

// RuntimeInfos lists all discovered plugin runtimes.
func (r *Runtime) RuntimeInfos(ctx context.Context, includeUnavailable bool) ([]*sandboxv1.RuntimeInfo, error) {
	plugins := discoverPlugins()
	if len(plugins) == 0 {
		return nil, nil
	}

	names := make([]string, 0, len(plugins))
	for name := range plugins {
		names = append(names, name)
	}
	slices.Sort(names)

	var infos []*sandboxv1.RuntimeInfo
	for _, name := range names {
		execPath := plugins[name]
		plugin, err := r.getPlugin(ctx, name, execPath)
		if err != nil {
			if includeUnavailable {
				infos = append(infos, &sandboxv1.RuntimeInfo{
					Runtime:           sandboxv1.Runtime_RUNTIME_PLUGIN,
					DisplayName:       name,
					PluginName:        name,
					Available:         false,
					UnavailableReason: err.Error(),
				})
			}
			continue
		}

		info := plugin.info
		displayName := firstNonEmpty(info.GetDisplayName(), info.GetName(), name)
		infos = append(infos, &sandboxv1.RuntimeInfo{
			Runtime:        sandboxv1.Runtime_RUNTIME_PLUGIN,
			DisplayName:    displayName,
			Version:        info.GetVersion(),
			Available:      true,
			SupportedModes: info.GetSupportedModes(),
			Capabilities:   info.GetCapabilities(),
			PluginName:     firstNonEmpty(info.GetName(), name),
		})
	}

	return infos, nil
}

// Available reports whether any sandbox plugin runtime is available.
func (r *Runtime) Available(ctx context.Context) bool {
	infos, err := r.RuntimeInfos(ctx, false)
	return err == nil && len(infos) > 0
}

// Version returns the first discovered plugin version, if any.
func (r *Runtime) Version(ctx context.Context) string {
	infos, err := r.RuntimeInfos(ctx, false)
	if err != nil || len(infos) == 0 {
		return ""
	}
	return infos[0].GetVersion()
}

// Capabilities returns the first discovered plugin capabilities, if any.
func (r *Runtime) Capabilities() *sandboxv1.RuntimeCapabilities {
	infos, err := r.RuntimeInfos(context.Background(), false)
	if err != nil || len(infos) == 0 {
		return &sandboxv1.RuntimeCapabilities{}
	}
	return infos[0].GetCapabilities()
}

// Execute runs a command via the selected plugin runtime.
func (r *Runtime) Execute(ctx context.Context, req *sandboxv1.ExecuteRequest) iter.Seq2[*sandboxv1.ExecuteEvent, error] {
	return func(yield func(*sandboxv1.ExecuteEvent, error) bool) {
		executionID := sandbox.GenerateExecutionID("plugin")

		// Validate command input
		if err := sandbox.ValidateCommand(req.GetCommand()); err != nil {
			yield(errorEvent(executionID, "INVALID_COMMAND", err.Error()), nil)
			return
		}

		// Validate workspace path (if any)
		if workspaceDir := req.GetWorkspaceDir(); workspaceDir != "" {
			if err := sandbox.ValidatePath(workspaceDir); err != nil {
				yield(errorEvent(executionID, "PATH_BLOCKED", err.Error()), nil)
				return
			}
		}

		cfg := req.GetConfig()
		pluginName := strings.TrimSpace(cfg.GetPluginName())
		if pluginName == "" {
			yield(errorEvent(executionID, "PLUGIN_REQUIRED", "plugin_name is required for plugin runtime"), nil)
			return
		}

		// Filter dangerous environment variables
		filteredEnv, _ := sandbox.FilterEnvVars(req.GetEnv())

		plugin, err := r.getPlugin(ctx, pluginName, "")
		if err != nil {
			yield(errorEvent(executionID, "PLUGIN_UNAVAILABLE", err.Error()), nil)
			return
		}

		execReq := &sandboxv1.RuntimeExecuteRequest{
			Command:      req.GetCommand(),
			Config:       cfg,
			WorkDir:      req.GetWorkDir(),
			Env:          filteredEnv,
			Stdin:        req.GetStdin(),
			Timeout:      req.GetTimeout(),
			WorkspaceDir: req.GetWorkspaceDir(),
			ExecutionId:  executionID,
			TraceContext: "",
		}
		if ctxInfo := req.GetContext(); ctxInfo != nil {
			execReq.TraceContext = ctxInfo.GetTraceContext()
		}

		stream, err := plugin.client.Execute(ctx, connect.NewRequest(execReq))
		if err != nil {
			yield(errorEvent(executionID, "PLUGIN_EXECUTE_FAILED", err.Error()), nil)
			return
		}
		defer stream.Close()

		for stream.Receive() {
			event := stream.Msg()
			if !yield(event, nil) {
				return
			}
		}

		if err := stream.Err(); err != nil && !errors.Is(err, context.Canceled) {
			yield(errorEvent(executionID, "PLUGIN_STREAM_FAILED", err.Error()), nil)
		}
	}
}

// Cleanup requests cleanup from the selected plugin runtime.
func (r *Runtime) Cleanup(ctx context.Context, executionID string) error {
	return fmt.Errorf("cleanup is not supported for plugin runtime without a plugin name")
}

// Close terminates any running plugin processes.
func (r *Runtime) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	var errs []error
	for name, plugin := range r.plugins {
		if err := plugin.close(); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		}
	}
	r.plugins = make(map[string]*pluginClient)
	if len(errs) > 0 {
		return fmt.Errorf("close plugins: %v", errs)
	}
	return nil
}

func (r *Runtime) getPlugin(ctx context.Context, name, execPath string) (*pluginClient, error) {
	r.mu.RLock()
	if plugin, ok := r.plugins[name]; ok {
		r.mu.RUnlock()
		return plugin, nil
	}
	r.mu.RUnlock()

	if execPath == "" {
		execPath = FindPluginInPath(name)
	}
	if execPath == "" {
		return nil, fmt.Errorf("plugin %q not found in PATH", name)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if plugin, ok := r.plugins[name]; ok {
		return plugin, nil
	}

	plugin, err := startPlugin(ctx, name, execPath)
	if err != nil {
		return nil, err
	}
	r.plugins[name] = plugin
	return plugin, nil
}

func startPlugin(ctx context.Context, name, execPath string) (*pluginClient, error) {
	tmpDir, err := os.MkdirTemp("", "deputy-sandbox-*")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}

	socketPath := filepath.Join(tmpDir, "sandbox.sock")
	cmd := exec.CommandContext(ctx, execPath, "--socket", socketPath)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard

	if err := cmd.Start(); err != nil {
		_ = os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("start plugin %q: %w", name, err)
	}

	if err := waitForSocket(socketPath, socketWaitTimeout); err != nil {
		_ = cmd.Process.Kill()
		_ = os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("plugin %q socket not ready: %w", name, err)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
	}

	client := sandboxv1connect.NewSandboxRuntimeServiceClient(httpClient, "http://localhost")
	resp, err := client.GetInfo(ctx, connect.NewRequest(&sandboxv1.GetRuntimeInfoRequest{}))
	if err != nil {
		_ = cmd.Process.Kill()
		_ = os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("plugin %q info failed: %w", name, err)
	}

	return &pluginClient{
		name:       name,
		execPath:   execPath,
		socketDir:  tmpDir,
		socketPath: socketPath,
		cmd:        cmd,
		client:     client,
		info:       resp.Msg,
	}, nil
}

func (p *pluginClient) close() error {
	if p == nil {
		return nil
	}
	if p.cmd != nil && p.cmd.Process != nil {
		_ = p.cmd.Process.Signal(os.Interrupt)
		done := make(chan error, 1)
		go func() {
			done <- p.cmd.Wait()
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = p.cmd.Process.Kill()
		}
	}

	if p.socketDir != "" {
		_ = os.RemoveAll(p.socketDir)
	}
	return nil
}

func waitForSocket(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for socket")
}

func discoverPlugins() map[string]string {
	pathEnv := os.Getenv("PATH")
	if pathEnv == "" {
		return nil
	}

	plugins := make(map[string]string)
	seen := make(map[string]bool)
	for _, dir := range filepath.SplitList(pathEnv) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			if !strings.HasPrefix(name, PluginPrefix) {
				continue
			}

			pluginName := strings.TrimPrefix(name, PluginPrefix)
			if pluginName == "" || seen[pluginName] {
				continue
			}

			execPath := filepath.Join(dir, name)
			info, err := os.Stat(execPath)
			if err != nil || info.Mode()&0111 == 0 {
				continue
			}

			seen[pluginName] = true
			plugins[pluginName] = execPath
		}
	}

	return plugins
}

// FindPluginInPath returns the full path to a sandbox plugin executable.
func FindPluginInPath(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	return discoverPlugins()[name]
}

func errorEvent(executionID, code, message string) *sandboxv1.ExecuteEvent {
	return &sandboxv1.ExecuteEvent{
		ExecutionId: executionID,
		Timestamp:   timestamppb.Now(),
		Details: &sandboxv1.ExecuteEvent_Error{
			Error: &sandboxv1.ErrorEvent{
				Message: message,
				Code:    code,
				IsFatal: true,
			},
		},
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
