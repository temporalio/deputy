//go:build darwin && arm64

// deputy-sandbox-vz is a sandbox runtime plugin using Apple's Virtualization.framework.
//
// This plugin provides VM-based isolation on macOS Apple Silicon using the vz library
// (https://github.com/Code-Hex/vz). Each sandbox execution runs in an isolated lightweight VM.
//
// Requirements:
//   - macOS 11.0+ (Big Sur or later)
//   - Apple Silicon (arm64)
//   - Code signing with virtualization entitlements
//   - Linux kernel and initrd/rootfs for guest
//
// The plugin expects these assets in ~/.deputy/vz/ or configurable via environment:
//   - DEPUTY_VZ_KERNEL: Path to Linux kernel (vmlinuz)
//   - DEPUTY_VZ_INITRD: Path to initrd (optional)
//   - DEPUTY_VZ_ROOTFS: Path to root filesystem disk image
//
// Installation:
//
//	go build -o deputy-sandbox-vz .
//	codesign --entitlements entitlements.plist --sign - deputy-sandbox-vz
//	mv deputy-sandbox-vz ~/bin/  # or somewhere in PATH
//
// Usage:
//
//	deputy exec --runtime plugin --plugin vz -- ls -la
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"connectrpc.com/connect"
	"github.com/Code-Hex/vz/v3"
	"github.com/creack/pty"
	"golang.org/x/term"
	sandboxv1 "github.com/picatz/deputy/gen/deputy/sandbox/v1"
	"github.com/picatz/deputy/gen/deputy/sandbox/v1/sandboxv1connect"
	deputyotel "github.com/picatz/deputy/internal/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	pluginName    = "vz"
	pluginVersion = "0.1.0"

	// Environment variables for asset paths
	envKernelPath = "DEPUTY_VZ_KERNEL"
	envInitrdPath = "DEPUTY_VZ_INITRD"
	envRootfsPath = "DEPUTY_VZ_ROOTFS"

	// Default locations
	defaultAssetDir = ".deputy/vz"

	// Protocol markers for parsing VM output
	// The init script wraps output with these markers so we can distinguish
	// command output from kernel/boot messages.
	outputStartMarker  = "<<<DEPUTY_OUTPUT_START>>>"
	outputEndMarker    = "<<<DEPUTY_OUTPUT_END>>>"
	exitCodeMarker     = "<<<DEPUTY_EXIT_CODE:"
	stderrMarker       = "<<<DEPUTY_STDERR>>>"
	stdoutMarker       = "<<<DEPUTY_STDOUT>>>"
	changesStartMarker   = "<<<DEPUTY_CHANGES_START>>>"
	changesEndMarker     = "<<<DEPUTY_CHANGES_END>>>"
	changeMarker         = "<<<DEPUTY_CHANGE:"
	netAuditStartMarker  = "<<<DEPUTY_NETAUDIT_START>>>"
	netAuditEndMarker    = "<<<DEPUTY_NETAUDIT_END>>>"
	netAuditMarker       = "<<<DEPUTY_NETAUDIT:"

	// Environment variable for Deputy proxy URL
	// When set, the VZ plugin will configure the VM to route package manager
	// traffic through the Deputy proxy for policy enforcement.
	envProxyURL = "DEPUTY_VZ_PROXY"

	// Environment variable for strict proxy mode
	// When "true" and proxy is configured with allowlist mode:
	// - Removes ",direct" fallback from GOPROXY (forces all traffic through proxy)
	// - Blocks DNS queries in nftables (pre-resolves all allowlist hosts at boot)
	// - Makes proxy bypass significantly harder
	envStrictProxy = "DEPUTY_VZ_STRICT_PROXY"

	// Environment variable for non-root execution
	// When set, the command will be executed as this user instead of root.
	// This provides defense-in-depth by reducing privilege inside the VM.
	// Common values: "nobody", "deputy", or a custom username.
	// The user will be created if it doesn't exist in the rootfs.
	envUser = "DEPUTY_VZ_USER"
)

// shellQuote quotes a string for safe use in shell commands.
// It wraps the string in single quotes and escapes any embedded single quotes.
func shellQuote(s string) string {
	// If the string is safe (alphanumeric, dash, underscore, dot, slash), no quoting needed
	safe := true
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '/') {
			safe = false
			break
		}
	}
	if safe && len(s) > 0 {
		return s
	}
	// Quote with single quotes, escaping any embedded single quotes
	// 'foo'\''bar' => foo'bar
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

// shellJoin quotes and joins command arguments for safe shell execution.
func shellJoin(args []string) string {
	quoted := make([]string, len(args))
	for i, arg := range args {
		quoted[i] = shellQuote(arg)
	}
	return strings.Join(quoted, " ")
}

// keysOnly extracts just the keys from a map for logging (avoids logging sensitive values).
func keysOnly(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func main() {
	socketPath := flag.String("socket", "", "Unix socket path to listen on")
	flag.Parse()

	if *socketPath == "" {
		log.Fatal("--socket is required")
	}

	// Configure logging to match Deputy's DEPUTY_LOG_LEVEL
	// Default to Warn level to reduce noise (consistent with Deputy CLI)
	logLevel := slog.LevelWarn
	if levelStr := os.Getenv("DEPUTY_LOG_LEVEL"); levelStr != "" {
		switch strings.ToLower(levelStr) {
		case "debug":
			logLevel = slog.LevelDebug
		case "info":
			logLevel = slog.LevelInfo
		case "warn", "warning":
			logLevel = slog.LevelWarn
		case "error":
			logLevel = slog.LevelError
		}
	}
	// Wrap slog handler with TraceContextHandler for log/trace correlation
	// This adds trace_id and span_id to log records when a span is active in the context
	baseHandler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: logLevel,
	})
	logger := slog.New(deputyotel.NewTraceContextHandler(baseHandler))
	slog.SetDefault(logger)

	handler := &vzHandler{
		logger: logger,
		vms:    make(map[string]*vmInstance),
	}

	mux := http.NewServeMux()
	mux.Handle(sandboxv1connect.NewSandboxRuntimeServiceHandler(handler))

	listener, err := net.Listen("unix", *socketPath)
	if err != nil {
		log.Fatalf("failed to listen on %s: %v", *socketPath, err)
	}
	defer listener.Close()

	server := &http.Server{
		Handler: h2c.NewHandler(mux, &http2.Server{}),
	}

	// Handle shutdown gracefully
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		handler.Shutdown()
		server.Close()
	}()

	slog.Debug("vz sandbox plugin listening", "socket", *socketPath)
	if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}

type vmInstance struct {
	vm              *vz.VirtualMachine
	cancel          context.CancelFunc
	startTime       time.Time
	changesDir      string           // Temp directory for workspace changes (review_before_commit)
	workspaceConfig *workspaceConfig // Workspace configuration for change syncing
}

type vzHandler struct {
	sandboxv1connect.UnimplementedSandboxRuntimeServiceHandler

	logger *slog.Logger

	mu  sync.RWMutex
	vms map[string]*vmInstance
}

func (h *vzHandler) GetInfo(
	ctx context.Context,
	req *connect.Request[sandboxv1.GetRuntimeInfoRequest],
) (*connect.Response[sandboxv1.GetRuntimeInfoResponse], error) {
	available := h.checkAvailability()

	return connect.NewResponse(&sandboxv1.GetRuntimeInfoResponse{
		Name:        pluginName,
		DisplayName: "Apple Virtualization (vz)",
		Version:     pluginVersion,
		Description: "VM-based sandbox using macOS Virtualization.framework",
		Capabilities: &sandboxv1.RuntimeCapabilities{
			NetworkIsolation:    true,
			FilesystemIsolation: true,
			ResourceLimits:      true,
			Seccomp:             false, // VMs don't use seccomp
			Apparmor:            false,
			Selinux:             false,
			UserNamespaces:      false, // N/A for VMs
			Rootless:            true,  // No root required
			GpuSupport:          false, // Not implemented yet
			StreamingOutput:     true,
			InteractiveStdin:    true,
		},
		SupportedModes: []sandboxv1.Mode{
			sandboxv1.Mode_MODE_READ_ONLY,
			sandboxv1.Mode_MODE_WORKSPACE_WRITE,
			sandboxv1.Mode_MODE_EPHEMERAL,
			sandboxv1.Mode_MODE_NETWORK_ISOLATED,
		},
	}), available
}

func (h *vzHandler) Execute(
	ctx context.Context,
	req *connect.Request[sandboxv1.RuntimeExecuteRequest],
	stream *connect.ServerStream[sandboxv1.ExecuteEvent],
) error {
	execReq := req.Msg
	executionID := execReq.GetExecutionId()
	if executionID == "" {
		executionID = fmt.Sprintf("vz-%d", time.Now().UnixNano())
	}

	// Validate command is provided
	if len(execReq.GetCommand()) == 0 {
		return stream.Send(h.errorEvent(executionID, "INVALID_REQUEST", "command is required"))
	}

	// Extract trace context from request for distributed tracing
	// This links the VZ plugin span to the parent span from the Deputy CLI/server
	if traceContext := execReq.GetTraceContext(); traceContext != "" {
		carrier := propagation.MapCarrier{"traceparent": traceContext}
		ctx = propagation.TraceContext{}.Extract(ctx, carrier)
	}

	// Start OTel span for VM execution (as child of extracted trace context)
	ctx, span := deputyotel.StartSpan(ctx, "deputy.sandbox.vz.execute",
		trace.WithAttributes(
			attribute.String("deputy.sandbox.execution_id", executionID),
			attribute.String("deputy.sandbox.runtime", "vz"),
			attribute.String("deputy.sandbox.mode", execReq.GetConfig().GetMode().String()),
			attribute.String("deputy.sandbox.network_mode", execReq.GetConfig().GetNetworkMode().String()),
		),
	)
	defer span.End()

	// Validate assets exist
	kernelPath, initrdPath, rootfsPath, err := h.resolveAssetPaths()
	if err != nil {
		deputyotel.SetSpanError(span, err)
		return stream.Send(h.errorEvent(executionID, "ASSET_ERROR", err.Error()))
	}
	slog.DebugContext(ctx, "VZ assets resolved", "kernel", kernelPath, "initrd", initrdPath, "rootfs", rootfsPath)
	span.SetAttributes(attribute.String("deputy.sandbox.vz.kernel", kernelPath))

	// For MODE_EPHEMERAL, create an APFS clone of the rootfs
	// This provides copy-on-write isolation - changes are discarded after execution
	config := execReq.GetConfig()

	// Check for two-phase execution mode
	twoPhaseConfig := config.GetTwoPhaseConfig()
	if twoPhaseConfig != nil && twoPhaseConfig.GetEnabled() {
		return h.executeTwoPhase(ctx, req, stream, executionID, kernelPath, initrdPath, rootfsPath)
	}

	var ephemeral *ephemeralRootfs
	if config.GetMode() == sandboxv1.Mode_MODE_EPHEMERAL {
		slog.DebugContext(ctx, "Creating ephemeral rootfs clone", "base", rootfsPath)
		ephemeral, err = newEphemeralRootfs(rootfsPath)
		if err != nil {
			return stream.Send(h.errorEvent(executionID, "EPHEMERAL_ERROR", err.Error()))
		}
		defer func() {
			if cleanupErr := ephemeral.Cleanup(); cleanupErr != nil {
				slog.Warn("Failed to cleanup ephemeral rootfs", "error", cleanupErr)
			}
		}()
		rootfsPath = ephemeral.Path()
		slog.DebugContext(ctx, "Using ephemeral rootfs", "path", rootfsPath)
	}

	// Create workspace configuration FIRST so we know the effective path to mount
	// For git worktree mode, this creates the worktree and gives us the worktree path
	wsConfig, err := newWorkspaceConfig(execReq.GetWorkspaceDir(), execReq.GetConfig())
	if err != nil {
		slog.ErrorContext(ctx, "Workspace config creation failed", "error", err)
		return stream.Send(h.errorEvent(executionID, "WORKSPACE_ERROR", err.Error()))
	}
	// Defer cleanup of workspace (worktree removal, temp dir cleanup)
	if wsConfig != nil {
		defer func() {
			slog.DebugContext(ctx, "Running workspace cleanup defer")
			if cleanupErr := wsConfig.Cleanup(); cleanupErr != nil {
				slog.Warn("Failed to cleanup workspace", "error", cleanupErr)
			}
		}()
	}

	// Determine effective workspace path - use worktree/snapshot path if available
	effectiveWorkspacePath := execReq.GetWorkspaceDir()
	if wsConfig != nil && wsConfig.directPath != "" {
		effectiveWorkspacePath = wsConfig.directPath
		slog.DebugContext(ctx, "Using effective workspace path from config",
			"original", execReq.GetWorkspaceDir(),
			"effective", effectiveWorkspacePath)
	}

	// Create PTY for VM console I/O (PTY works better than pipes with Virtualization.framework)
	ptyPrimary, ptySecondary, err := pty.Open()
	if err != nil {
		return stream.Send(h.errorEvent(executionID, "PTY_ERROR", fmt.Sprintf("failed to create PTY: %v", err)))
	}
	defer ptyPrimary.Close()
	defer ptySecondary.Close()

	// Set initial PTY window size from host terminal
	// For interactive commands (vim, less, etc.), we use actual terminal size.
	// For non-interactive, large default prevents spurious line wrapping.
	isInteractive := term.IsTerminal(int(os.Stdin.Fd()))
	cols, rows := 32767, 24 // Large default for non-interactive to avoid wrapping
	if isInteractive {
		if width, height, err := term.GetSize(int(os.Stdout.Fd())); err == nil && width > 0 {
			cols, rows = width, height
		}
	}
	if err := pty.Setsize(ptySecondary, &pty.Winsize{Rows: uint16(rows), Cols: uint16(cols)}); err != nil {
		h.logger.Debug("failed to set PTY size", "err", err)
	}

	// Set up SIGWINCH handler for dynamic PTY resizing (interactive terminals only)
	// This enables proper terminal behavior for vim, less, and other TUI applications
	var winchCh chan os.Signal
	if isInteractive {
		winchCh = make(chan os.Signal, 1)
		signal.Notify(winchCh, syscall.SIGWINCH)
		defer signal.Stop(winchCh)

		// Goroutine to handle terminal resize events
		go func() {
			for range winchCh {
				if width, height, err := term.GetSize(int(os.Stdout.Fd())); err == nil && width > 0 {
					if err := pty.Setsize(ptySecondary, &pty.Winsize{Rows: uint16(height), Cols: uint16(width)}); err != nil {
						slog.Debug("failed to resize PTY on SIGWINCH", "err", err)
					} else {
						slog.DebugContext(ctx, "PTY resized", "cols", width, "rows", height)
					}
				}
			}
		}()
	}

	// Put PTY primary in raw mode to prevent line discipline transformations
	// This ensures binary-clean output without \n -> \r\n conversion or echo
	oldState, err := term.MakeRaw(int(ptyPrimary.Fd()))
	if err != nil {
		return stream.Send(h.errorEvent(executionID, "PTY_ERROR", fmt.Sprintf("failed to set raw mode: %v", err)))
	}
	defer term.Restore(int(ptyPrimary.Fd()), oldState)

	// Create VM configuration with the PTY secondary (VM reads/writes to secondary, we read/write to primary)
	// Pass the effective workspace path (may be worktree path for git-worktree mode)
	slog.DebugContext(ctx, "Creating VM config", "kernel", kernelPath, "initrd", initrdPath, "rootfs", rootfsPath)
	vmConfig, changesDir, err := h.createVMConfigWithWorkspace(execReq, kernelPath, initrdPath, rootfsPath, ptySecondary, ptySecondary, effectiveWorkspacePath)
	if err != nil {
		slog.ErrorContext(ctx, "VM config creation failed", "error", err)
		return stream.Send(h.errorEvent(executionID, "CONFIG_ERROR", err.Error()))
	}
	// Clean up changes directory on function exit if it was created
	if changesDir != "" {
		defer func() {
			// Only clean up if not preserving for review
			if !execReq.GetConfig().GetWorkspaceIsolationConfig().GetPreserveAfterExecution() {
				os.RemoveAll(changesDir)
			}
		}()
	}
	slog.DebugContext(ctx, "VM config created successfully", "changesDir", changesDir)

	// If changes directory was created, update the workspace config's upper path
	if changesDir != "" && wsConfig != nil {
		wsConfig.upperPath = changesDir
		wsConfig.preserveChanges = true // Preserve for the review workflow
	}

	// Validate configuration
	slog.DebugContext(ctx, "Validating VM config")
	validated, err := vmConfig.Validate()
	if err != nil {
		slog.ErrorContext(ctx, "VM config validation error", "error", err)
		return stream.Send(h.errorEvent(executionID, "VALIDATION_ERROR", err.Error()))
	}
	if !validated {
		slog.ErrorContext(ctx, "VM config validation returned false")
		return stream.Send(h.errorEvent(executionID, "VALIDATION_ERROR", "VM configuration validation failed"))
	}
	slog.DebugContext(ctx, "VM config validated successfully")

	// Create the VM
	slog.DebugContext(ctx, "Creating VirtualMachine instance")
	deputyotel.AddSpanEvent(span, "vm.creating")
	vm, err := vz.NewVirtualMachine(vmConfig)
	if err != nil {
		slog.ErrorContext(ctx, "VM creation failed", "error", err)
		deputyotel.SetSpanError(span, err)
		return stream.Send(h.errorEvent(executionID, "VM_CREATE_ERROR", err.Error()))
	}
	slog.DebugContext(ctx, "VirtualMachine instance created")
	deputyotel.AddSpanEvent(span, "vm.created")

	// Create cancellable context for the VM
	vmCtx, vmCancel := context.WithCancel(ctx)

	// Track the VM
	h.mu.Lock()
	h.vms[executionID] = &vmInstance{
		vm:              vm,
		cancel:          vmCancel,
		startTime:       time.Now(),
		changesDir:      changesDir,
		workspaceConfig: wsConfig,
	}
	h.mu.Unlock()

	defer func() {
		vmCancel()
		h.mu.Lock()
		delete(h.vms, executionID)
		h.mu.Unlock()
	}()

	// Send started event
	if err := stream.Send(&sandboxv1.ExecuteEvent{
		ExecutionId: executionID,
		Timestamp:   timestamppb.Now(),
		Details: &sandboxv1.ExecuteEvent_Started{
			Started: &sandboxv1.StartedEvent{
				ExecutionId:     executionID,
				Runtime:         sandboxv1.Runtime_RUNTIME_PLUGIN,
				EffectiveConfig: execReq.GetConfig(),
			},
		},
	}); err != nil {
		return err
	}

	// Start output parser goroutine
	outputDone := make(chan *executionResult, 1)
	go h.parseVMOutput(vmCtx, ptyPrimary, stream, executionID, outputDone)

	// Start the VM
	startTime := time.Now()
	h.logger.Debug("Starting VM", "executionID", executionID, "kernel", kernelPath, "rootfs", rootfsPath, "vmState", vm.State())
	deputyotel.AddSpanEvent(span, "vm.starting")
	if err := vm.Start(); err != nil {
		h.logger.Error("VM start failed", "error", err, "vmState", vm.State())
		deputyotel.SetSpanError(span, err)
		return stream.Send(h.errorEvent(executionID, "VM_START_ERROR", err.Error()))
	}

	h.logger.Debug("VM started successfully", "executionID", executionID, "state", vm.State())
	deputyotel.AddSpanEvent(span, "vm.started")

	// Set up timeout if specified
	var timeoutCh <-chan time.Time
	if timeout := execReq.GetTimeout(); timeout != nil && timeout.AsDuration() > 0 {
		timeoutCh = time.After(timeout.AsDuration())
	}

	// Wait for completion
	var exitCode int32 = 0
	var execErr error
	var execResult *executionResult // Store full result for network audit export

	select {
	case <-vmCtx.Done():
		// Context cancelled
		h.logger.Debug("VM context cancelled", "executionID", executionID)
		if vm.CanStop() {
			_ = vm.Stop()
		}
		exitCode = 137

	case <-timeoutCh:
		// Timeout reached
		h.logger.Debug("VM timeout reached", "executionID", executionID)
		if vm.CanStop() {
			_ = vm.Stop()
		}
		execErr = fmt.Errorf("execution timeout")
		exitCode = 124

	case result := <-outputDone:
		// Command completed - we got exit code from parsed output
		h.logger.Debug("VM command completed", "executionID", executionID, "exitCode", result.exitCode)
		execResult = result
		exitCode = result.exitCode
		if result.err != nil && exitCode == 0 {
			exitCode = 1
		}
		// Wait for VM to stop gracefully (deputy-init runs sync; poweroff -f)
		// This ensures filesystem writes are flushed before we return
		h.logger.Debug("Waiting for VM to stop gracefully", "executionID", executionID)
		select {
		case <-waitForVMState(vm):
			h.logger.Debug("VM stopped gracefully", "executionID", executionID)
		case <-vmCtx.Done():
			// Context cancelled (e.g., CTRL+C) - force stop immediately
			h.logger.Debug("Context cancelled, forcing VM stop", "executionID", executionID)
			if vm.CanStop() {
				_ = vm.Stop()
			}
		case <-time.After(60 * time.Second):
			// Timeout waiting for graceful shutdown, force stop
			h.logger.Debug("VM graceful shutdown timeout, forcing stop", "executionID", executionID)
			if vm.CanStop() {
				_ = vm.Stop()
			}
		}

	case state := <-waitForVMState(vm):
		// VM stopped unexpectedly
		h.logger.Debug("VM state changed", "executionID", executionID, "state", state)
		switch state {
		case vz.VirtualMachineStateStopped:
			// Check if we got a result
			select {
			case result := <-outputDone:
				exitCode = result.exitCode
			default:
				exitCode = 0
			}
		case vz.VirtualMachineStateError:
			exitCode = 1
			execErr = fmt.Errorf("VM error state")
		}
	}

	if execErr != nil {
		deputyotel.SetSpanError(span, execErr)
		if err := stream.Send(h.errorEvent(executionID, "EXECUTION_ERROR", execErr.Error())); err != nil {
			return err
		}
	}

	// Send completed event
	duration := time.Since(startTime)

	// Export network audit entries as OTel span events
	// This provides visibility into network connections made by the sandboxed command
	if execResult != nil && len(execResult.netAudit) > 0 {
		for _, entry := range execResult.netAudit {
			eventName := "network.connection"
			if entry.Action == "DROP" {
				eventName = "network.connection.blocked"
			}
			deputyotel.AddSpanEvent(span, eventName,
				attribute.String("deputy.sandbox.network.action", entry.Action),
				attribute.String("deputy.sandbox.network.protocol", entry.Protocol),
				attribute.String("deputy.sandbox.network.destination", entry.Destination),
				attribute.Int("deputy.sandbox.network.port", entry.Port),
			)
		}
		// Also record summary attributes on the span
		var allowCount, dropCount int
		for _, entry := range execResult.netAudit {
			if entry.Action == "DROP" {
				dropCount++
			} else {
				allowCount++
			}
		}
		span.SetAttributes(
			attribute.Int("deputy.sandbox.network.connections_total", len(execResult.netAudit)),
			attribute.Int("deputy.sandbox.network.connections_allowed", allowCount),
			attribute.Int("deputy.sandbox.network.connections_blocked", dropCount),
		)
		slog.DebugContext(ctx, "Network audit exported to OTel",
			"total", len(execResult.netAudit),
			"allowed", allowCount,
			"blocked", dropCount)
	}

	// Record final span attributes
	deputyotel.AddSpanEvent(span, "vm.completed",
		attribute.Int("exit_code", int(exitCode)),
		attribute.Int64("duration_ms", duration.Milliseconds()),
	)
	span.SetAttributes(
		attribute.Int("deputy.sandbox.exit_code", int(exitCode)),
		attribute.Int64("deputy.sandbox.duration_ms", duration.Milliseconds()),
	)
	if exitCode == 0 && execErr == nil {
		deputyotel.SetSpanOK(span)
	}

	return stream.Send(&sandboxv1.ExecuteEvent{
		ExecutionId: executionID,
		Timestamp:   timestamppb.Now(),
		Details: &sandboxv1.ExecuteEvent_Completed{
			Completed: &sandboxv1.CompletedEvent{
				ExitCode: exitCode,
				Duration: durationpb.New(duration),
			},
		},
	})
}

// executeTwoPhase implements two-phase execution for supply chain security.
// Phase 1: Pre-fetch dependencies with network access (no code execution)
// Phase 2: Build/run command offline (network disabled)
//
// This prevents supply chain attacks where malicious code:
// - Exfiltrates source code or secrets during build
// - Downloads additional payloads at build time
// - Communicates with C2 servers during execution
func (h *vzHandler) executeTwoPhase(
	ctx context.Context,
	req *connect.Request[sandboxv1.RuntimeExecuteRequest],
	stream *connect.ServerStream[sandboxv1.ExecuteEvent],
	executionID string,
	kernelPath, initrdPath, rootfsPath string,
) error {
	execReq := req.Msg
	config := execReq.GetConfig()
	twoPhaseConfig := config.GetTwoPhaseConfig()

	h.logger.Info("Starting two-phase execution",
		"executionID", executionID,
		"prefetchCommand", twoPhaseConfig.GetPrefetchCommand(),
		"mainCommand", execReq.GetCommand())

	// Create ephemeral rootfs for isolation (changes persist between phases)
	ephemeral, err := newEphemeralRootfs(rootfsPath)
	if err != nil {
		return stream.Send(h.errorEvent(executionID, "EPHEMERAL_ERROR", err.Error()))
	}
	defer func() {
		if cleanupErr := ephemeral.Cleanup(); cleanupErr != nil {
			slog.Warn("Failed to cleanup ephemeral rootfs", "error", cleanupErr)
		}
	}()
	ephemeralRootfs := ephemeral.Path()

	// ========== PHASE 1: Pre-fetch with network access ==========
	if len(twoPhaseConfig.GetPrefetchCommand()) > 0 {
		h.logger.Info("Phase 1: Pre-fetching dependencies with network access",
			"executionID", executionID,
			"command", twoPhaseConfig.GetPrefetchCommand())

		// Send phase notification
		if err := stream.Send(&sandboxv1.ExecuteEvent{
			ExecutionId: executionID,
			Timestamp:   timestamppb.Now(),
			Details: &sandboxv1.ExecuteEvent_Output{
				Output: &sandboxv1.OutputEvent{
					Data:     []byte("[Phase 1/2] Pre-fetching dependencies (network enabled)...\n"),
					IsStderr: false,
				},
			},
		}); err != nil {
			return err
		}

		// Create phase 1 config with network access
		phase1Config := cloneSandboxConfig(config)

		// Use prefetch-specific network allowlist if provided
		if len(twoPhaseConfig.GetPrefetchNetworkAllowlist()) > 0 {
			phase1Config.NetworkMode = sandboxv1.NetworkMode_NETWORK_MODE_ALLOWLIST
			phase1Config.NetworkAllowlist = twoPhaseConfig.GetPrefetchNetworkAllowlist()
		} else if phase1Config.GetNetworkMode() == sandboxv1.NetworkMode_NETWORK_MODE_NONE {
			// If network was disabled, enable it for pre-fetch
			phase1Config.NetworkMode = sandboxv1.NetworkMode_NETWORK_MODE_HOST
		}

		// Build phase 1 request
		phase1Req := &sandboxv1.RuntimeExecuteRequest{
			ExecutionId:  executionID + "-prefetch",
			Command:      twoPhaseConfig.GetPrefetchCommand(),
			Config:       phase1Config,
			WorkDir:      execReq.GetWorkDir(),
			Env:          execReq.GetEnv(),
			Timeout:      twoPhaseConfig.GetPrefetchTimeout(),
			WorkspaceDir: execReq.GetWorkspaceDir(),
		}

		// Set default prefetch timeout if not specified
		if phase1Req.Timeout == nil {
			phase1Req.Timeout = durationpb.New(10 * time.Minute)
		}

		// Execute phase 1
		exitCode, err := h.executePhase(ctx, phase1Req, stream, kernelPath, initrdPath, ephemeralRootfs)
		if err != nil {
			return stream.Send(h.errorEvent(executionID, "PREFETCH_ERROR", err.Error()))
		}
		if exitCode != 0 {
			h.logger.Error("Pre-fetch phase failed", "exitCode", exitCode)
			return stream.Send(&sandboxv1.ExecuteEvent{
				ExecutionId: executionID,
				Timestamp:   timestamppb.Now(),
				Details: &sandboxv1.ExecuteEvent_Completed{
					Completed: &sandboxv1.CompletedEvent{
						ExitCode: exitCode,
					},
				},
			})
		}

		h.logger.Info("Phase 1 completed successfully", "executionID", executionID)
	}

	// ========== PHASE 2: Build/run offline ==========
	h.logger.Info("Phase 2: Running command offline (network disabled)",
		"executionID", executionID,
		"command", execReq.GetCommand())

	// Send phase notification
	if err := stream.Send(&sandboxv1.ExecuteEvent{
		ExecutionId: executionID,
		Timestamp:   timestamppb.Now(),
		Details: &sandboxv1.ExecuteEvent_Output{
			Output: &sandboxv1.OutputEvent{
				Data:     []byte("[Phase 2/2] Running build offline (network disabled)...\n"),
				IsStderr: false,
			},
		},
	}); err != nil {
		return err
	}

	// Create phase 2 config with network DISABLED
	phase2Config := cloneSandboxConfig(config)
	phase2Config.NetworkMode = sandboxv1.NetworkMode_NETWORK_MODE_NONE
	phase2Config.NetworkAllowlist = nil // Clear any allowlist
	phase2Config.TwoPhaseConfig = nil   // Clear to prevent recursion

	// Build phase 2 request with the original command
	phase2Req := &sandboxv1.RuntimeExecuteRequest{
		ExecutionId:  executionID,
		Command:      execReq.GetCommand(),
		Config:       phase2Config,
		WorkDir:      execReq.GetWorkDir(),
		Env:          execReq.GetEnv(),
		Timeout:      execReq.GetTimeout(),
		WorkspaceDir: execReq.GetWorkspaceDir(),
	}

	// Execute phase 2 (offline)
	exitCode, err := h.executePhase(ctx, phase2Req, stream, kernelPath, initrdPath, ephemeralRootfs)
	if err != nil {
		return stream.Send(h.errorEvent(executionID, "BUILD_ERROR", err.Error()))
	}

	h.logger.Info("Two-phase execution completed",
		"executionID", executionID,
		"exitCode", exitCode)

	return stream.Send(&sandboxv1.ExecuteEvent{
		ExecutionId: executionID,
		Timestamp:   timestamppb.Now(),
		Details: &sandboxv1.ExecuteEvent_Completed{
			Completed: &sandboxv1.CompletedEvent{
				ExitCode: exitCode,
			},
		},
	})
}

// executePhase runs a single phase of execution and returns the exit code.
// This is a simplified version of Execute that returns instead of streaming completion.
func (h *vzHandler) executePhase(
	ctx context.Context,
	execReq *sandboxv1.RuntimeExecuteRequest,
	stream *connect.ServerStream[sandboxv1.ExecuteEvent],
	kernelPath, initrdPath, rootfsPath string,
) (int32, error) {
	executionID := execReq.GetExecutionId()

	// Create PTY for VM console I/O
	ptyPrimary, ptySecondary, err := pty.Open()
	if err != nil {
		return 1, fmt.Errorf("failed to create PTY: %w", err)
	}
	defer ptyPrimary.Close()
	defer ptySecondary.Close()

	// Set PTY window size
	cols, rows := 32767, 24
	if width, height, err := term.GetSize(int(os.Stdout.Fd())); err == nil && width > 0 {
		cols, rows = width, height
	}
	_ = pty.Setsize(ptySecondary, &pty.Winsize{Rows: uint16(rows), Cols: uint16(cols)})

	// Put PTY in raw mode
	oldState, err := term.MakeRaw(int(ptyPrimary.Fd()))
	if err != nil {
		return 1, fmt.Errorf("failed to set raw mode: %w", err)
	}
	defer term.Restore(int(ptyPrimary.Fd()), oldState)

	// Create VM configuration
	vmConfig, _, err := h.createVMConfig(execReq, kernelPath, initrdPath, rootfsPath, ptySecondary, ptySecondary)
	if err != nil {
		return 1, fmt.Errorf("create VM config: %w", err)
	}

	// Validate configuration
	if validated, err := vmConfig.Validate(); err != nil || !validated {
		return 1, fmt.Errorf("VM config validation failed: %v", err)
	}

	// Create the VM
	vm, err := vz.NewVirtualMachine(vmConfig)
	if err != nil {
		return 1, fmt.Errorf("create VM: %w", err)
	}

	// Create cancellable context
	vmCtx, vmCancel := context.WithCancel(ctx)
	defer vmCancel()

	// Start output parser
	outputDone := make(chan *executionResult, 1)
	go h.parseVMOutput(vmCtx, ptyPrimary, stream, executionID, outputDone)

	// Start the VM
	if err := vm.Start(); err != nil {
		return 1, fmt.Errorf("start VM: %w", err)
	}

	// Set up timeout
	var timeoutCh <-chan time.Time
	if timeout := execReq.GetTimeout(); timeout != nil && timeout.AsDuration() > 0 {
		timeoutCh = time.After(timeout.AsDuration())
	}

	// Wait for completion
	var exitCode int32 = 0

	select {
	case <-vmCtx.Done():
		if vm.CanStop() {
			_ = vm.Stop()
		}
		return 137, ctx.Err()

	case <-timeoutCh:
		if vm.CanStop() {
			_ = vm.Stop()
		}
		return 124, fmt.Errorf("execution timeout")

	case result := <-outputDone:
		exitCode = result.exitCode
		// Wait for VM to stop gracefully
		select {
		case <-waitForVMState(vm):
		case <-vmCtx.Done():
			if vm.CanStop() {
				_ = vm.Stop()
			}
		case <-time.After(60 * time.Second):
			if vm.CanStop() {
				_ = vm.Stop()
			}
		}

	case state := <-waitForVMState(vm):
		switch state {
		case vz.VirtualMachineStateStopped:
			select {
			case result := <-outputDone:
				exitCode = result.exitCode
			default:
			}
		case vz.VirtualMachineStateError:
			return 1, fmt.Errorf("VM error state")
		}
	}

	return exitCode, nil
}

// cloneSandboxConfig creates a shallow copy of SandboxConfig for phase modifications.
func cloneSandboxConfig(config *sandboxv1.SandboxConfig) *sandboxv1.SandboxConfig {
	if config == nil {
		return &sandboxv1.SandboxConfig{}
	}
	// Create a new config with the same values
	return &sandboxv1.SandboxConfig{
		Runtime:                  config.GetRuntime(),
		Mode:                     config.GetMode(),
		NetworkMode:              config.GetNetworkMode(),
		Image:                    config.GetImage(),
		Limits:                   config.GetLimits(),
		Mounts:                   config.GetMounts(),
		NetworkAllowlist:         config.GetNetworkAllowlist(),
		DropCapabilities:         config.GetDropCapabilities(),
		AddCapabilities:          config.GetAddCapabilities(),
		SeccompProfile:           config.GetSeccompProfile(),
		User:                     config.GetUser(),
		Group:                    config.GetGroup(),
		ReadOnlyPaths:            config.GetReadOnlyPaths(),
		HiddenPaths:              config.GetHiddenPaths(),
		PluginName:               config.GetPluginName(),
		ExtraOptions:             config.GetExtraOptions(),
		ExecAllowlist:            config.GetExecAllowlist(),
		WorkspaceIsolation:       config.GetWorkspaceIsolation(),
		FileMask:                 config.GetFileMask(),
		ReviewBeforeCommit:       config.GetReviewBeforeCommit(),
		WorkspaceIsolationConfig: config.GetWorkspaceIsolationConfig(),
		TwoPhaseConfig:           config.GetTwoPhaseConfig(),
	}
}

// executionResult holds the result of parsing VM output
type executionResult struct {
	exitCode    int32
	err         error
	changes     []fileChange    // Changed files (for review_before_commit)
	netAudit    []netAuditEntry // Network connection audit log
}

// fileChange represents a file change from overlay mode
type fileChange struct {
	Type string // "A" (added), "M" (modified), "D" (deleted)
	Path string // Relative path
}

// netAuditEntry represents an audited network connection
type netAuditEntry struct {
	Action      string // "ALLOW" or "DROP"
	Protocol    string // "TCP", "UDP", etc.
	Destination string // IP address
	Port        int    // Destination port (0 if not applicable)
}

// parseVMOutput reads the VM console output, filters boot messages,
// and streams command output back via the gRPC stream.
func (h *vzHandler) parseVMOutput(
	ctx context.Context,
	reader io.Reader,
	stream *connect.ServerStream[sandboxv1.ExecuteEvent],
	executionID string,
	done chan<- *executionResult,
) {
	defer close(done)
	h.logger.Debug("parseVMOutput started", "executionID", executionID)

	result := &executionResult{exitCode: 0}
	var outputBuf bytes.Buffer  // Buffered user output to send
	var lineBuf bytes.Buffer    // Partial line buffer for chunk boundary handling
	var allOutput bytes.Buffer  // Debug: all raw output
	inOutput := false
	isStderr := false
	inChanges := false
	buf := make([]byte, 4096)

	// processLine handles a complete line (without trailing newline)
	processLine := func(line string) bool {
		line = strings.TrimRight(line, "\r")

		// Check for protocol markers
		if strings.Contains(line, outputStartMarker) {
			inOutput = true
			isStderr = false
			return true
		}
		if strings.Contains(line, outputEndMarker) {
			if outputBuf.Len() > 0 {
				h.sendOutput(stream, executionID, outputBuf.Bytes(), isStderr)
				outputBuf.Reset()
			}
			inOutput = false
			return true
		}
		if strings.Contains(line, exitCodeMarker) {
			start := strings.Index(line, exitCodeMarker) + len(exitCodeMarker)
			end := strings.Index(line[start:], ">>>")
			if end > 0 {
				if code, parseErr := strconv.ParseInt(line[start:start+end], 10, 32); parseErr == nil {
					result.exitCode = int32(code)
				}
			}
			h.logger.Debug("parseVMOutput exit code found", "exitCode", result.exitCode)
			// Don't exit here - continue to parse changes if review_before_commit is enabled
			return true
		}
		if strings.Contains(line, stderrMarker) {
			if outputBuf.Len() > 0 && !isStderr {
				h.sendOutput(stream, executionID, outputBuf.Bytes(), false)
				outputBuf.Reset()
			}
			isStderr = true
			return true
		}
		if strings.Contains(line, stdoutMarker) {
			if outputBuf.Len() > 0 && isStderr {
				h.sendOutput(stream, executionID, outputBuf.Bytes(), true)
				outputBuf.Reset()
			}
			isStderr = false
			return true
		}

		// Check for changes markers (review_before_commit workflow)
		if strings.Contains(line, changesStartMarker) {
			inChanges = true
			h.logger.Debug("parseVMOutput changes section started")
			return true
		}
		if strings.Contains(line, changesEndMarker) {
			inChanges = false
			h.logger.Debug("parseVMOutput changes section ended", "changes", len(result.changes))
			// Don't exit yet - there might be netaudit section after
			return true
		}
		if inChanges && strings.Contains(line, changeMarker) {
			// Parse <<<DEPUTY_CHANGE:type:path>>>
			start := strings.Index(line, changeMarker) + len(changeMarker)
			end := strings.Index(line[start:], ">>>")
			if end > 0 {
				content := line[start : start+end]
				// Format is "type:path" where type is A/M/D
				parts := strings.SplitN(content, ":", 2)
				if len(parts) == 2 {
					result.changes = append(result.changes, fileChange{
						Type: parts[0],
						Path: parts[1],
					})
					h.logger.Debug("parseVMOutput change detected", "type", parts[0], "path", parts[1])
				}
			}
			return true
		}

		// Check for network audit markers
		if strings.Contains(line, netAuditStartMarker) {
			h.logger.Debug("parseVMOutput netaudit section started")
			return true
		}
		if strings.Contains(line, netAuditEndMarker) {
			h.logger.Debug("parseVMOutput netaudit section ended", "entries", len(result.netAudit))
			return false // All done - exit after netaudit section (last section)
		}
		if strings.Contains(line, netAuditMarker) {
			// Parse <<<DEPUTY_NETAUDIT:action:proto:dest:port>>>
			start := strings.Index(line, netAuditMarker) + len(netAuditMarker)
			end := strings.Index(line[start:], ">>>")
			if end > 0 {
				content := line[start : start+end]
				// Format is "action:proto:dest:port"
				parts := strings.SplitN(content, ":", 4)
				if len(parts) >= 3 {
					entry := netAuditEntry{
						Action:      parts[0],
						Protocol:    parts[1],
						Destination: parts[2],
					}
					if len(parts) >= 4 {
						if port, err := strconv.Atoi(parts[3]); err == nil {
							entry.Port = port
						}
					}
					result.netAudit = append(result.netAudit, entry)
					h.logger.Debug("parseVMOutput netaudit entry",
						"action", entry.Action,
						"proto", entry.Protocol,
						"dest", entry.Destination,
						"port", entry.Port)
				}
			}
			return true
		}

		// Buffer output if in output section
		if inOutput {
			outputBuf.WriteString(line)
			outputBuf.WriteByte('\n')
			if outputBuf.Len() > 4096 {
				h.sendOutput(stream, executionID, outputBuf.Bytes(), isStderr)
				outputBuf.Reset()
			}
		}
		return true
	}

	for {
		select {
		case <-ctx.Done():
			h.logger.Debug("parseVMOutput context done", "totalOutput", allOutput.Len())
			done <- result
			return
		default:
		}

		n, err := reader.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			allOutput.Write(chunk)
			h.logger.Debug("RAW_READ", "bytes", n, "data", string(chunk))

			// Process chunk byte by byte, handling line boundaries correctly
			for _, b := range chunk {
				if b == '\n' {
					// Complete line ready
					if !processLine(lineBuf.String()) {
						done <- result
						return
					}
					lineBuf.Reset()
				} else {
					lineBuf.WriteByte(b)
				}
			}
		}

		if err != nil {
			h.logger.Debug("parseVMOutput read error", "err", err, "totalOutput", allOutput.Len())
			// Process any remaining partial line
			if lineBuf.Len() > 0 {
				processLine(lineBuf.String())
			}
			if outputBuf.Len() > 0 {
				h.sendOutput(stream, executionID, outputBuf.Bytes(), isStderr)
			}
			done <- result
			return
		}
	}
}

func (h *vzHandler) sendOutput(
	stream *connect.ServerStream[sandboxv1.ExecuteEvent],
	executionID string,
	data []byte,
	isStderr bool,
) {
	if len(data) == 0 {
		return
	}

	_ = stream.Send(&sandboxv1.ExecuteEvent{
		ExecutionId: executionID,
		Timestamp:   timestamppb.Now(),
		Details: &sandboxv1.ExecuteEvent_Output{
			Output: &sandboxv1.OutputEvent{
				Data:     data,
				IsStderr: isStderr,
			},
		},
	})
}

func (h *vzHandler) Cleanup(
	ctx context.Context,
	req *connect.Request[sandboxv1.CleanupRequest],
) (*connect.Response[sandboxv1.CleanupResponse], error) {
	executionID := req.Msg.GetExecutionId()

	h.mu.Lock()
	instance, ok := h.vms[executionID]
	if ok {
		delete(h.vms, executionID)
	}
	h.mu.Unlock()

	if !ok {
		return connect.NewResponse(&sandboxv1.CleanupResponse{
			Success: true,
		}), nil
	}

	// Cancel the VM context
	instance.cancel()

	// Try to stop the VM
	if instance.vm.CanStop() {
		if err := instance.vm.Stop(); err != nil {
			return connect.NewResponse(&sandboxv1.CleanupResponse{
				Success: false,
				Error:   fmt.Sprintf("failed to stop VM: %v", err),
			}), nil
		}
	}

	return connect.NewResponse(&sandboxv1.CleanupResponse{
		Success: true,
	}), nil
}

// SyncChanges copies workspace changes from the sandbox to the original workspace.
// This is used after execution when review_before_commit is enabled.
// The user reviews the changes, then calls this to accept them.
// Note: This does NOT create a git commit - the user commits manually.
func (h *vzHandler) SyncChanges(
	ctx context.Context,
	req *connect.Request[sandboxv1.SyncChangesRequest],
) (*connect.Response[sandboxv1.SyncChangesResponse], error) {
	executionID := req.Msg.GetExecutionId()

	h.mu.RLock()
	instance, ok := h.vms[executionID]
	h.mu.RUnlock()

	if !ok {
		return connect.NewResponse(&sandboxv1.SyncChangesResponse{
			Success: false,
			Error:   fmt.Sprintf("execution %s not found", executionID),
		}), nil
	}

	wsConfig := instance.workspaceConfig
	if wsConfig == nil {
		return connect.NewResponse(&sandboxv1.SyncChangesResponse{
			Success: false,
			Error:   "no workspace configured for this execution",
		}), nil
	}

	// Get the list of changed files first
	changedFiles, err := wsConfig.GetChangedFiles()
	if err != nil {
		return connect.NewResponse(&sandboxv1.SyncChangesResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to get changed files: %v", err),
		}), nil
	}

	if len(changedFiles) == 0 {
		return connect.NewResponse(&sandboxv1.SyncChangesResponse{
			Success:     true,
			FilesSynced: 0,
			SyncedFiles: nil,
		}), nil
	}

	// Apply include/exclude filters if specified
	includePatterns := req.Msg.GetIncludePatterns()
	excludePatterns := req.Msg.GetExcludePatterns()

	var filesToSync []string
	for _, f := range changedFiles {
		// Check exclude patterns first
		excluded := false
		for _, pattern := range excludePatterns {
			if matched, _ := filepath.Match(pattern, f); matched {
				excluded = true
				break
			}
		}
		if excluded {
			continue
		}

		// Check include patterns (if any specified)
		if len(includePatterns) > 0 {
			included := false
			for _, pattern := range includePatterns {
				if matched, _ := filepath.Match(pattern, f); matched {
					included = true
					break
				}
			}
			if !included {
				continue
			}
		}

		filesToSync = append(filesToSync, f)
	}

	// Sync the changes
	if err := wsConfig.SyncChangesToOriginal(); err != nil {
		return connect.NewResponse(&sandboxv1.SyncChangesResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to sync changes: %v", err),
		}), nil
	}

	h.logger.Info("Synced workspace changes",
		"executionID", executionID,
		"files", len(filesToSync))

	return connect.NewResponse(&sandboxv1.SyncChangesResponse{
		Success:     true,
		FilesSynced: int32(len(filesToSync)),
		SyncedFiles: filesToSync,
	}), nil
}

// GetChanges returns the list of files changed during execution.
// This is used for the change review workflow.
func (h *vzHandler) GetChanges(
	ctx context.Context,
	req *connect.Request[sandboxv1.GetChangesRequest],
) (*connect.Response[sandboxv1.GetChangesResponse], error) {
	executionID := req.Msg.GetExecutionId()

	h.mu.RLock()
	instance, ok := h.vms[executionID]
	h.mu.RUnlock()

	if !ok {
		return connect.NewResponse(&sandboxv1.GetChangesResponse{
			Changes:      nil,
			TotalChanges: 0,
		}), nil
	}

	wsConfig := instance.workspaceConfig
	if wsConfig == nil {
		return connect.NewResponse(&sandboxv1.GetChangesResponse{
			Changes:      nil,
			TotalChanges: 0,
		}), nil
	}

	// Get the list of changed files
	changedFiles, err := wsConfig.GetChangedFiles()
	if err != nil {
		h.logger.Warn("Failed to get changed files", "error", err)
		return connect.NewResponse(&sandboxv1.GetChangesResponse{
			Changes:      nil,
			TotalChanges: 0,
		}), nil
	}

	// Build the response with file details
	changes := make([]*sandboxv1.FileChange, 0, len(changedFiles))
	for _, f := range changedFiles {
		change := &sandboxv1.FileChange{
			Path:       f,
			ChangeType: "modified", // Default to modified
		}

		// Try to get more details about the change
		changesPath := wsConfig.GetChangesPath()
		if changesPath != "" {
			fullPath := filepath.Join(changesPath, f)
			if info, err := os.Stat(fullPath); err == nil {
				change.Size = info.Size()
			} else if os.IsNotExist(err) {
				change.ChangeType = "deleted"
			}
		}

		// Check if it's a new file (doesn't exist in original)
		originalPath := wsConfig.GetOriginalPath()
		if originalPath != "" && change.ChangeType != "deleted" {
			origFile := filepath.Join(originalPath, f)
			if _, err := os.Stat(origFile); os.IsNotExist(err) {
				change.ChangeType = "added"
			}
		}

		changes = append(changes, change)
	}

	return connect.NewResponse(&sandboxv1.GetChangesResponse{
		Changes:      changes,
		TotalChanges: int32(len(changes)),
	}), nil
}

func (h *vzHandler) Shutdown() {
	h.mu.Lock()
	defer h.mu.Unlock()

	for id, instance := range h.vms {
		instance.cancel()
		if instance.vm.CanStop() {
			_ = instance.vm.Stop()
		}
		delete(h.vms, id)
	}
}

func (h *vzHandler) checkAvailability() error {
	// Check for required assets (vz library handles availability checks internally)
	_, _, _, err := h.resolveAssetPaths()
	return err
}

func (h *vzHandler) resolveAssetPaths() (kernel, initrd, rootfs string, err error) {
	// Check environment variables first
	kernel = os.Getenv(envKernelPath)
	initrd = os.Getenv(envInitrdPath)
	rootfs = os.Getenv(envRootfsPath)

	// Fall back to default locations
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", "", "", fmt.Errorf("cannot determine home directory: %w", err)
	}

	assetDir := filepath.Join(homeDir, defaultAssetDir)

	if kernel == "" {
		kernel = filepath.Join(assetDir, "vmlinuz")
	}
	if rootfs == "" {
		rootfs = filepath.Join(assetDir, "rootfs.img")
	}

	// Validate kernel exists
	if _, err := os.Stat(kernel); os.IsNotExist(err) {
		return "", "", "", fmt.Errorf("kernel not found at %s (set %s)", kernel, envKernelPath)
	}

	// Validate rootfs exists
	if _, err := os.Stat(rootfs); os.IsNotExist(err) {
		return "", "", "", fmt.Errorf("rootfs not found at %s (set %s)", rootfs, envRootfsPath)
	}

	// Check for initrd (optional - Alpine needs it, Ubuntu doesn't)
	// If not set via env, check for initrd.img in same directory as kernel
	if initrd == "" {
		defaultInitrd := filepath.Join(assetDir, "alpine", "initrd.img")
		if _, err := os.Stat(defaultInitrd); err == nil {
			initrd = defaultInitrd
		}
	}
	// Validate initrd if specified
	if initrd != "" {
		if _, err := os.Stat(initrd); os.IsNotExist(err) {
			return "", "", "", fmt.Errorf("initrd not found at %s (set %s)", initrd, envInitrdPath)
		}
	}

	return kernel, initrd, rootfs, nil
}

func (h *vzHandler) createVMConfig(
	req *sandboxv1.RuntimeExecuteRequest,
	kernelPath, initrdPath, rootfsPath string,
	stdinFile, stdoutFile *os.File,
) (*vz.VirtualMachineConfiguration, string, error) {
	// Use the workspace path from the request (no override)
	return h.createVMConfigWithWorkspace(req, kernelPath, initrdPath, rootfsPath, stdinFile, stdoutFile, "")
}

// createVMConfigWithWorkspace creates VM configuration with an optional workspace path override.
// If effectiveWorkspacePath is non-empty, it will be used instead of req.GetWorkspaceDir()
// for mounting. This is used for git-worktree mode where we mount the worktree path
// instead of the original workspace.
func (h *vzHandler) createVMConfigWithWorkspace(
	req *sandboxv1.RuntimeExecuteRequest,
	kernelPath, initrdPath, rootfsPath string,
	stdinFile, stdoutFile *os.File,
	effectiveWorkspacePath string,
) (*vz.VirtualMachineConfiguration, string, error) {
	config := req.GetConfig()

	// Determine memory (default 512MB)
	memoryBytes := uint64(512 * 1024 * 1024)
	if limits := config.GetLimits(); limits != nil && limits.GetMemory() != "" {
		// Parse memory string like "1g" or "512m"
		parsed, err := parseMemoryString(limits.GetMemory())
		if err == nil {
			memoryBytes = parsed
		}
	}

	// CPU count (default 1)
	cpuCount := uint(1)
	if limits := config.GetLimits(); limits != nil && limits.GetCpu() != "" {
		// Parse CPU string like "2.0"
		var cpu float64
		if _, err := fmt.Sscanf(limits.GetCpu(), "%f", &cpu); err == nil && cpu >= 1 {
			cpuCount = uint(cpu)
		}
	}

	// Encode the command to execute in base64 to safely pass it via kernel cmdline
	// We use a special kernel parameter "deputy.cmd" to pass the command
	// Each argument is shell-quoted to preserve spaces and special characters
	// The init script uses eval to execute the resulting shell command
	command := req.GetCommand()
	cmdEncoded := base64.StdEncoding.EncodeToString([]byte(shellJoin(command)))

	// Build kernel command line
	// The disk is always attached as /dev/vda.
	// We use init=/deputy-init which reads the command from the deputy.cmd parameter
	//
	// Note: Root mount mode (ro/rw) must match the disk attachment mode.
	// If the disk is attached as read-only, the kernel must also mount it read-only,
	// otherwise the boot hangs trying to remount as rw.
	rootMountMode := "rw"
	if config.GetMode() == sandboxv1.Mode_MODE_READ_ONLY {
		rootMountMode = "ro"
	}
	cmdline := fmt.Sprintf("console=hvc0 root=/dev/vda %s init=/deputy-init deputy.cmd=%s", rootMountMode, cmdEncoded)

	// Pass host time to VM for clock synchronization (VMs boot at epoch by default)
	// This fixes SSL/TLS certificate validation which fails when clock is at 1970
	cmdline += fmt.Sprintf(" deputy.time=%d", time.Now().Unix())

	// Pass workdir to VM - this is the directory to cd into before executing
	// When workspace is mounted via virtio-fs at /workspace, we use relative paths
	if workDir := req.GetWorkDir(); workDir != "" {
		cmdline += fmt.Sprintf(" deputy.workdir=%s", workDir)
	} else if req.GetWorkspaceDir() != "" {
		// Default to /workspace if workspace is being shared
		cmdline += " deputy.workdir=/workspace"
	}

	// Pass network allowlist to VM if ALLOWLIST mode is enabled
	// The init script will configure nftables rules based on this list.
	// Format: base64-encoded newline-separated list of "host:port" or "host" entries.
	// We always pass the parameter in ALLOWLIST mode (even if empty) to signal the init
	// script to set up the DROP policy for egress filtering.
	// Special marker: "__DEPUTY_ALLOWLIST_EMPTY__" signals empty allowlist (DROP all)
	if config.GetNetworkMode() == sandboxv1.NetworkMode_NETWORK_MODE_ALLOWLIST {
		allowlist := config.GetNetworkAllowlist()
		var allowlistStr string
		if len(allowlist) == 0 {
			// Use sentinel value to signal empty allowlist (triggers DROP policy)
			allowlistStr = "__DEPUTY_ALLOWLIST_EMPTY__"
		} else {
			// Join allowlist entries with newlines
			allowlistStr = strings.Join(allowlist, "\n")
		}
		allowlistEncoded := base64.StdEncoding.EncodeToString([]byte(allowlistStr))
		cmdline += fmt.Sprintf(" deputy.allowlist=%s", allowlistEncoded)
		slog.Debug("VZ allowlist passed to kernel",
			"entries", len(allowlist),
			"hosts", allowlist)
	}

	// Pass Deputy proxy URL to VM if configured
	// The proxy URL is used to route package manager traffic through Deputy
	// for policy enforcement (vulnerability scanning, license checks, etc.)
	proxyURL := os.Getenv(envProxyURL)
	strictProxy := os.Getenv(envStrictProxy) == "true"
	if proxyURL != "" {
		// Base64 encode to safely pass through kernel cmdline
		proxyEncoded := base64.StdEncoding.EncodeToString([]byte(proxyURL))
		cmdline += fmt.Sprintf(" deputy.proxy=%s", proxyEncoded)

		// Strict proxy mode: when enabled with allowlist, provides stronger security
		// by removing fallback options and blocking DNS (pre-resolved at boot)
		if strictProxy {
			cmdline += " deputy.strict_proxy=1"
			slog.Debug("VZ strict proxy mode enabled",
				"proxyURL", proxyURL,
				"note", "DNS blocked, no direct fallback - proxy bypass hardened")
		} else {
			slog.Debug("VZ proxy configured",
				"proxyURL", proxyURL,
				"note", "VM will route package manager traffic through Deputy proxy")
		}
	}

	// Pass non-root user to VM if configured
	// This enables defense-in-depth by running commands as unprivileged user
	if runAsUser := os.Getenv(envUser); runAsUser != "" {
		// Also check sandbox config for user setting (proto takes precedence)
		if config.GetUser() != "" {
			runAsUser = config.GetUser()
		}
		userEncoded := base64.StdEncoding.EncodeToString([]byte(runAsUser))
		cmdline += fmt.Sprintf(" deputy.user=%s", userEncoded)
		slog.Debug("VZ non-root execution enabled",
			"user", runAsUser,
			"note", "command will run as unprivileged user inside VM")
	} else if config.GetUser() != "" {
		// User specified in sandbox config
		userEncoded := base64.StdEncoding.EncodeToString([]byte(config.GetUser()))
		cmdline += fmt.Sprintf(" deputy.user=%s", userEncoded)
		slog.Debug("VZ non-root execution enabled (from config)",
			"user", config.GetUser())
	}

	// Pass network audit mode to VM if enabled
	// This enables logging of blocked (and optionally allowed) network connections
	networkAudit := config.GetNetworkAudit()
	switch networkAudit {
	case sandboxv1.NetworkAuditMode_NETWORK_AUDIT_MODE_BLOCKED:
		cmdline += " deputy.netaudit=1"
		slog.Debug("VZ network audit enabled (blocked connections only)")
	case sandboxv1.NetworkAuditMode_NETWORK_AUDIT_MODE_ALL:
		cmdline += " deputy.netaudit=2"
		slog.Debug("VZ network audit enabled (all connections)")
	}

	// Pass user-specified environment variables to VM
	// Format: base64-encoded newline-separated "KEY=VALUE" pairs
	// Security: We only pass explicitly provided env vars, not the host environment
	if envVars := req.GetEnv(); len(envVars) > 0 {
		var envPairs []string
		for k, v := range envVars {
			envPairs = append(envPairs, k+"="+v)
		}
		envEncoded := base64.StdEncoding.EncodeToString([]byte(strings.Join(envPairs, "\n")))
		cmdline += fmt.Sprintf(" deputy.env=%s", envEncoded)
		slog.Debug("VZ environment variables passed to VM",
			"count", len(envVars),
			"keys", keysOnly(envVars))
	}

	// Pass stdin data to VM if provided
	// For small data (<32KB), pass via kernel cmdline as base64
	// For larger data, we'd need to write to a file shared via virtiofs (future enhancement)
	const maxKernelStdinSize = 32 * 1024 // 32KB limit for kernel cmdline
	if stdin := req.GetStdin(); len(stdin) > 0 {
		if len(stdin) > maxKernelStdinSize {
			slog.Warn("VZ stdin data exceeds kernel cmdline limit, truncating",
				"size", len(stdin),
				"limit", maxKernelStdinSize)
			stdin = stdin[:maxKernelStdinSize]
		}
		stdinEncoded := base64.StdEncoding.EncodeToString(stdin)
		cmdline += fmt.Sprintf(" deputy.stdin=%s", stdinEncoded)
		slog.Debug("VZ stdin passed to VM",
			"size", len(stdin))
	}

	// Add quiet boot unless debug logging is enabled
	if os.Getenv("DEPUTY_LOG_LEVEL") != "debug" {
		cmdline += " quiet loglevel=3"
	} else {
		// Show boot messages for debugging
		cmdline += " loglevel=7"
	}

	// Create bootloader with optional initrd
	// Alpine needs initrd (has virtiofs module), Ubuntu boots directly to rootfs
	slog.Debug("creating bootloader",
		"kernel", kernelPath,
		"initrd", initrdPath,
		"cmdline", cmdline)
	var bootloader *vz.LinuxBootLoader
	var err error
	if initrdPath != "" {
		bootloader, err = vz.NewLinuxBootLoader(kernelPath,
			vz.WithCommandLine(cmdline),
			vz.WithInitrd(initrdPath))
	} else {
		bootloader, err = vz.NewLinuxBootLoader(kernelPath, vz.WithCommandLine(cmdline))
	}
	if err != nil {
		return nil, "", fmt.Errorf("create bootloader: %w", err)
	}

	// Create VM configuration
	vmConfig, err := vz.NewVirtualMachineConfiguration(bootloader, cpuCount, memoryBytes)
	if err != nil {
		return nil, "", fmt.Errorf("create VM config: %w", err)
	}

	// Add serial console (for output streaming) using our pipes
	serialAttachment, err := vz.NewFileHandleSerialPortAttachment(stdinFile, stdoutFile)
	if err != nil {
		return nil, "", fmt.Errorf("create serial attachment: %w", err)
	}
	serialConfig, err := vz.NewVirtioConsoleDeviceSerialPortConfiguration(serialAttachment)
	if err != nil {
		return nil, "", fmt.Errorf("create serial config: %w", err)
	}
	vmConfig.SetSerialPortsVirtualMachineConfiguration([]*vz.VirtioConsoleDeviceSerialPortConfiguration{
		serialConfig,
	})

	// Add root disk with proper caching and synchronization settings
	// Using DiskImageCachingModeCached + DiskImageSynchronizationModeFsync (like Lima)
	// ensures that filesystem writes are properly flushed to disk, preventing
	// corrupt caches (e.g., Go toolchain downloads) when the VM shuts down.
	diskAttachment, err := vz.NewDiskImageStorageDeviceAttachmentWithCacheAndSync(
		rootfsPath,
		config.GetMode() == sandboxv1.Mode_MODE_READ_ONLY, // read-only based on mode
		vz.DiskImageCachingModeCached,
		vz.DiskImageSynchronizationModeFsync,
	)
	if err != nil {
		return nil, "", fmt.Errorf("create disk attachment: %w", err)
	}

	blockDevice, err := vz.NewVirtioBlockDeviceConfiguration(diskAttachment)
	if err != nil {
		return nil, "", fmt.Errorf("create block device: %w", err)
	}
	vmConfig.SetStorageDevicesVirtualMachineConfiguration([]vz.StorageDeviceConfiguration{
		blockDevice,
	})

	// Configure network based on network mode
	// VZ networking options in macOS Virtualization.framework:
	//
	// - NETWORK_MODE_NONE: No network device attached (maximum isolation)
	// - NETWORK_MODE_HOST: NAT via vmnet (private IP, NAT to host network)
	// - NETWORK_MODE_BRIDGE: Also uses NAT (true bridged requires com.apple.vm.networking
	//   entitlement which can't be used with ad-hoc signing)
	// - NETWORK_MODE_ALLOWLIST: NAT + nftables rules in guest kernel
	//
	// NAT networking uses Apple's vmnet framework which provides:
	// - DHCP for IP assignment (192.168.64.x range)
	// - NAT for outbound connectivity
	// - Note: vmnet gateway does NOT forward DNS - init script must configure public DNS
	networkMode := config.GetNetworkMode()
	slog.Debug("VZ network configuration",
		"networkMode", networkMode,
		"networkModeName", networkMode.String())

	if err := h.configureNetworkDevice(vmConfig, networkMode, config); err != nil {
		return nil, "", err
	}

	// Add entropy device for randomness
	entropyDevice, err := vz.NewVirtioEntropyDeviceConfiguration()
	if err != nil {
		return nil, "", fmt.Errorf("create entropy device: %w", err)
	}
	vmConfig.SetEntropyDevicesVirtualMachineConfiguration([]*vz.VirtioEntropyDeviceConfiguration{
		entropyDevice,
	})

	// Add memory balloon for dynamic memory
	balloonDevice, err := vz.NewVirtioTraditionalMemoryBalloonDeviceConfiguration()
	if err != nil {
		return nil, "", fmt.Errorf("create balloon device: %w", err)
	}
	vmConfig.SetMemoryBalloonDevicesVirtualMachineConfiguration([]vz.MemoryBalloonDeviceConfiguration{
		balloonDevice,
	})

	// Add workspace directory shares based on isolation mode
	// Use effective workspace path if provided (for git-worktree mode)
	wsResult, err := h.configureWorkspaceShares(req, config, effectiveWorkspacePath)
	if err != nil {
		return nil, "", fmt.Errorf("configure workspace: %w", err)
	}
	if len(wsResult.devices) > 0 {
		vmConfig.SetDirectorySharingDevicesVirtualMachineConfiguration(wsResult.devices)
	}

	return vmConfig, wsResult.changesDir, nil
}

// configureNetworkDevice sets up the network device based on the requested mode.
//
// Network modes in macOS Virtualization.framework:
//   - NONE: No network device attached (maximum isolation)
//   - HOST: NAT via vmnet (private IP 192.168.64.x, NAT to host network)
//   - BRIDGE: Uses NAT (true bridged requires com.apple.vm.networking entitlement)
//   - ALLOWLIST: NAT + guest-side nftables filtering (requires kernel netfilter support)
//   - UNSPECIFIED: Defaults to NONE for security
func (h *vzHandler) configureNetworkDevice(
	vmConfig *vz.VirtualMachineConfiguration,
	networkMode sandboxv1.NetworkMode,
	config *sandboxv1.SandboxConfig,
) error {
	switch networkMode {
	case sandboxv1.NetworkMode_NETWORK_MODE_NONE,
		sandboxv1.NetworkMode_NETWORK_MODE_UNSPECIFIED:
		// No network device - maximum isolation
		slog.Debug("VZ network disabled", "mode", networkMode.String())
		return nil

	case sandboxv1.NetworkMode_NETWORK_MODE_HOST:
		// NAT networking - VM gets private IP, can access host network via NAT
		return h.attachNATNetwork(vmConfig, "HOST")

	case sandboxv1.NetworkMode_NETWORK_MODE_BRIDGE:
		// Bridged networking - ideally would put VM on physical network
		// However, true bridged mode requires com.apple.vm.networking entitlement
		// which is restricted and can't be used with ad-hoc code signing.
		// We fall back to NAT which provides similar outbound connectivity.
		slog.Debug("VZ BRIDGE mode using NAT (bridged requires restricted entitlement)")
		return h.attachNATNetwork(vmConfig, "BRIDGE (NAT fallback)")

	case sandboxv1.NetworkMode_NETWORK_MODE_ALLOWLIST:
		// NAT + guest-side filtering using nftables
		// The allowlist is enforced via nftables rules in the guest kernel.
		// Note: Requires kernel with CONFIG_NETFILTER support.
		if err := h.attachNATNetwork(vmConfig, "ALLOWLIST"); err != nil {
			return err
		}

		// Log the allowlist for debugging
		allowlist := config.GetNetworkAllowlist()
		if len(allowlist) > 0 {
			slog.Debug("VZ network allowlist configured",
				"hosts", allowlist,
				"note", "enforcement via guest nftables")
		} else {
			slog.Warn("VZ ALLOWLIST mode but no hosts specified - all traffic will be blocked")
		}
		return nil

	default:
		return fmt.Errorf("unsupported network mode: %s", networkMode.String())
	}
}

// attachNATNetwork creates and attaches a NAT network device to the VM.
// NAT networking uses Apple's vmnet framework which provides:
// - DHCP for IP assignment (192.168.64.x range by default)
// - NAT for outbound connectivity to host network
// - Note: vmnet gateway does NOT forward DNS queries
func (h *vzHandler) attachNATNetwork(vmConfig *vz.VirtualMachineConfiguration, modeDesc string) error {
	natAttachment, err := vz.NewNATNetworkDeviceAttachment()
	if err != nil {
		return fmt.Errorf("create NAT attachment: %w", err)
	}

	networkDevice, err := vz.NewVirtioNetworkDeviceConfiguration(natAttachment)
	if err != nil {
		return fmt.Errorf("create network device: %w", err)
	}

	// Set a MAC address (required for proper device enumeration, like Lima does)
	// Using a locally administered MAC address prefix (52:55:55)
	macAddr, err := net.ParseMAC("52:55:55:00:00:01")
	if err != nil {
		return fmt.Errorf("parse MAC address: %w", err)
	}
	vzMAC, err := vz.NewMACAddress(macAddr)
	if err != nil {
		return fmt.Errorf("create VZ MAC address: %w", err)
	}
	networkDevice.SetMACAddress(vzMAC)

	vmConfig.SetNetworkDevicesVirtualMachineConfiguration([]*vz.VirtioNetworkDeviceConfiguration{
		networkDevice,
	})

	slog.Debug("VZ network device added",
		"type", "NAT",
		"mode", modeDesc,
		"mac", macAddr.String())

	return nil
}

// workspaceSharesResult holds the results of configuring workspace shares.
type workspaceSharesResult struct {
	devices    []vz.DirectorySharingDeviceConfiguration
	changesDir string // Temp directory for syncing changes (review_before_commit)
}

// configureWorkspaceShares sets up virtio-fs shares for the workspace.
// In direct mode, creates a single "workspace" share.
// In overlay mode, creates "workspace-base" (RO) share with local upper/work.
// When review_before_commit is enabled, also creates "workspace-changes" share
// for syncing changes back to the host.
//
// If effectiveWorkspacePath is non-empty, it overrides req.GetWorkspaceDir() for
// the actual mount path. This is used for git-worktree mode where we need to
// mount the worktree directory instead of the original workspace.
func (h *vzHandler) configureWorkspaceShares(
	req *sandboxv1.RuntimeExecuteRequest,
	config *sandboxv1.SandboxConfig,
	effectiveWorkspacePath string,
) (*workspaceSharesResult, error) {
	workspaceDir := req.GetWorkspaceDir()
	if workspaceDir == "" {
		return &workspaceSharesResult{}, nil
	}

	// Use effective path if provided (e.g., git worktree path)
	if effectiveWorkspacePath != "" {
		workspaceDir = effectiveWorkspacePath
	}

	result := &workspaceSharesResult{}

	// Check workspace isolation mode
	isolationMode := config.GetWorkspaceIsolation()
	isReadOnly := config.GetMode() == sandboxv1.Mode_MODE_READ_ONLY

	// Enable changes syncing if review_before_commit OR preserve_after_execution is set
	isolationConfig := config.GetWorkspaceIsolationConfig()
	reviewBeforeCommit := config.GetReviewBeforeCommit() ||
		(isolationConfig != nil && isolationConfig.GetPreserveAfterExecution())

	slog.Debug("Configuring workspace shares",
		"workspace", workspaceDir,
		"isolation_mode", isolationMode.String(),
		"is_read_only", isReadOnly,
		"review_before_commit", reviewBeforeCommit)

	switch isolationMode {
	case sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_OVERLAY:
		// Overlay mode: workspace-base (RO) via virtiofs, upper/work on local ext4
		// This provides isolation: host workspace is read-only, changes stay in VM.
		//
		// Note: We only create workspace-base share here. The guest init script
		// will mount it as lowerdir and use local ext4 directories for upperdir/workdir.
		// This avoids virtiofs permission issues with overlayfs workdir operations.
		baseDir, err := vz.NewSharedDirectory(workspaceDir, true) // Read-only
		if err != nil {
			return nil, fmt.Errorf("create workspace-base share: %w", err)
		}
		baseShare, err := vz.NewSingleDirectoryShare(baseDir)
		if err != nil {
			return nil, fmt.Errorf("create workspace-base directory share: %w", err)
		}
		baseFsDevice, err := vz.NewVirtioFileSystemDeviceConfiguration("workspace-base")
		if err != nil {
			return nil, fmt.Errorf("create workspace-base fs device: %w", err)
		}
		baseFsDevice.SetDirectoryShare(baseShare)
		result.devices = append(result.devices, baseFsDevice)

		// If review_before_commit is enabled, create a changes directory on the host
		// and share it via virtiofs so the VM can sync changes before shutdown.
		if reviewBeforeCommit {
			changesDir, err := os.MkdirTemp("", "deputy-vz-changes-*")
			if err != nil {
				return nil, fmt.Errorf("create changes temp dir: %w", err)
			}
			result.changesDir = changesDir

			changesSharedDir, err := vz.NewSharedDirectory(changesDir, false) // Read-write
			if err != nil {
				os.RemoveAll(changesDir)
				return nil, fmt.Errorf("create workspace-changes share: %w", err)
			}
			changesShare, err := vz.NewSingleDirectoryShare(changesSharedDir)
			if err != nil {
				os.RemoveAll(changesDir)
				return nil, fmt.Errorf("create workspace-changes directory share: %w", err)
			}
			changesFsDevice, err := vz.NewVirtioFileSystemDeviceConfiguration("workspace-changes")
			if err != nil {
				os.RemoveAll(changesDir)
				return nil, fmt.Errorf("create workspace-changes fs device: %w", err)
			}
			changesFsDevice.SetDirectoryShare(changesShare)
			result.devices = append(result.devices, changesFsDevice)

			slog.Debug("Configured workspace-changes share for review", "changesDir", changesDir)
		}

		slog.Debug("Configured overlay workspace (RO base, local upper/work)", "base", workspaceDir)

	case sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_GIT_WORKTREE:
		// Git worktree mode: share the worktree directory + the original .git directory
		// The worktree's .git file contains an absolute path that won't work in the VM,
		// so we also share the parent repo's .git directory and fix the path in deputy-init.

		// Share the worktree directory as "workspace"
		worktreeDir, err := vz.NewSharedDirectory(workspaceDir, false) // Read-write
		if err != nil {
			return nil, fmt.Errorf("create worktree share: %w", err)
		}
		worktreeShare, err := vz.NewSingleDirectoryShare(worktreeDir)
		if err != nil {
			return nil, fmt.Errorf("create worktree directory share: %w", err)
		}
		worktreeFsDevice, err := vz.NewVirtioFileSystemDeviceConfiguration("workspace")
		if err != nil {
			return nil, fmt.Errorf("create worktree fs device: %w", err)
		}
		worktreeFsDevice.SetDirectoryShare(worktreeShare)
		result.devices = append(result.devices, worktreeFsDevice)

		// Find the original repo's .git directory from the worktree's .git file
		gitFile := filepath.Join(workspaceDir, ".git")
		gitFileContent, err := os.ReadFile(gitFile)
		if err == nil && strings.HasPrefix(string(gitFileContent), "gitdir:") {
			// Parse: "gitdir: /path/to/repo/.git/worktrees/name"
			gitdirPath := strings.TrimSpace(strings.TrimPrefix(string(gitFileContent), "gitdir:"))
			// Go up from .git/worktrees/name to .git
			if strings.Contains(gitdirPath, ".git/worktrees/") {
				// Extract the main .git directory
				idx := strings.Index(gitdirPath, ".git/worktrees/")
				mainGitDir := gitdirPath[:idx+4] // Include ".git"

				// Share the main .git directory as "workspace-git"
				gitDir, err := vz.NewSharedDirectory(mainGitDir, false) // Read-write for index updates
				if err != nil {
					slog.Warn("Failed to share .git directory", "path", mainGitDir, "error", err)
				} else {
					gitShare, err := vz.NewSingleDirectoryShare(gitDir)
					if err != nil {
						slog.Warn("Failed to create .git share", "error", err)
					} else {
						gitFsDevice, err := vz.NewVirtioFileSystemDeviceConfiguration("workspace-git")
						if err != nil {
							slog.Warn("Failed to create .git fs device", "error", err)
						} else {
							gitFsDevice.SetDirectoryShare(gitShare)
							result.devices = append(result.devices, gitFsDevice)
							slog.Debug("Configured git worktree workspace",
								"worktree", workspaceDir,
								"gitDir", mainGitDir)
						}
					}
				}
			}
		}

		if len(result.devices) == 1 {
			// Only worktree was shared, warn that git operations may not work
			slog.Warn("Git worktree mode: could not share .git directory, git operations may fail")
		}

	default:
		// Direct mode: single workspace share
		sharedDir, err := vz.NewSharedDirectory(workspaceDir, isReadOnly)
		if err != nil {
			return nil, fmt.Errorf("create workspace share: %w", err)
		}
		shareConfig, err := vz.NewSingleDirectoryShare(sharedDir)
		if err != nil {
			return nil, fmt.Errorf("create workspace directory share: %w", err)
		}
		fsDevice, err := vz.NewVirtioFileSystemDeviceConfiguration("workspace")
		if err != nil {
			return nil, fmt.Errorf("create workspace fs device: %w", err)
		}
		fsDevice.SetDirectoryShare(shareConfig)
		result.devices = append(result.devices, fsDevice)

		slog.Debug("Configured direct workspace", "path", workspaceDir, "readOnly", isReadOnly)
	}

	return result, nil
}

func (h *vzHandler) errorEvent(executionID, code, message string) *sandboxv1.ExecuteEvent {
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

func waitForVMState(vm *vz.VirtualMachine) <-chan vz.VirtualMachineState {
	ch := make(chan vz.VirtualMachineState, 1)
	go func() {
		// Poll for state changes
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for range ticker.C {
			state := vm.State()
			if state == vz.VirtualMachineStateStopped ||
				state == vz.VirtualMachineStateError {
				ch <- state
				return
			}
		}
	}()
	return ch
}

func parseMemoryString(s string) (uint64, error) {
	var value uint64
	var unit string
	if _, err := fmt.Sscanf(s, "%d%s", &value, &unit); err != nil {
		// Try without unit
		if _, err := fmt.Sscanf(s, "%d", &value); err != nil {
			return 0, err
		}
		return value, nil
	}

	switch unit {
	case "k", "K", "kb", "KB":
		return value * 1024, nil
	case "m", "M", "mb", "MB":
		return value * 1024 * 1024, nil
	case "g", "G", "gb", "GB":
		return value * 1024 * 1024 * 1024, nil
	default:
		return value, nil
	}
}
