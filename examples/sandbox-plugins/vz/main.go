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
	sandboxv1 "github.com/picatz/deputy/gen/deputy/sandbox/v1"
	"github.com/picatz/deputy/gen/deputy/sandbox/v1/sandboxv1connect"
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
	outputStartMarker = "<<<DEPUTY_OUTPUT_START>>>"
	outputEndMarker   = "<<<DEPUTY_OUTPUT_END>>>"
	exitCodeMarker    = "<<<DEPUTY_EXIT_CODE:"
	stderrMarker      = "<<<DEPUTY_STDERR>>>"
	stdoutMarker      = "<<<DEPUTY_STDOUT>>>"
)

func main() {
	socketPath := flag.String("socket", "", "Unix socket path to listen on")
	flag.Parse()

	if *socketPath == "" {
		log.Fatal("--socket is required")
	}

	handler := &vzHandler{
		logger: slog.Default(),
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
	vm        *vz.VirtualMachine
	cancel    context.CancelFunc
	startTime time.Time
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

	// Validate assets exist
	kernelPath, initrdPath, rootfsPath, err := h.resolveAssetPaths()
	if err != nil {
		return stream.Send(h.errorEvent(executionID, "ASSET_ERROR", err.Error()))
	}
	slog.Debug("VZ assets resolved", "kernel", kernelPath, "initrd", initrdPath, "rootfs", rootfsPath)

	// Create PTY for VM console I/O (PTY works better than pipes with Virtualization.framework)
	ptyMaster, ptySlave, err := pty.Open()
	if err != nil {
		return stream.Send(h.errorEvent(executionID, "PTY_ERROR", fmt.Sprintf("failed to create PTY: %v", err)))
	}
	defer ptyMaster.Close()
	defer ptySlave.Close()

	// Create VM configuration with the PTY slave (VM reads/writes to slave, we read/write to master)
	vmConfig, err := h.createVMConfig(execReq, kernelPath, initrdPath, rootfsPath, ptySlave, ptySlave)
	if err != nil {
		return stream.Send(h.errorEvent(executionID, "CONFIG_ERROR", err.Error()))
	}

	// Validate configuration
	validated, err := vmConfig.Validate()
	if err != nil {
		return stream.Send(h.errorEvent(executionID, "VALIDATION_ERROR", err.Error()))
	}
	if !validated {
		return stream.Send(h.errorEvent(executionID, "VALIDATION_ERROR", "VM configuration validation failed"))
	}

	// Create the VM
	vm, err := vz.NewVirtualMachine(vmConfig)
	if err != nil {
		return stream.Send(h.errorEvent(executionID, "VM_CREATE_ERROR", err.Error()))
	}

	// Create cancellable context for the VM
	vmCtx, vmCancel := context.WithCancel(ctx)

	// Track the VM
	h.mu.Lock()
	h.vms[executionID] = &vmInstance{
		vm:        vm,
		cancel:    vmCancel,
		startTime: time.Now(),
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
	go h.parseVMOutput(vmCtx, ptyMaster, stream, executionID, outputDone)

	// Start the VM
	startTime := time.Now()
	h.logger.Debug("Starting VM", "executionID", executionID, "kernel", kernelPath, "rootfs", rootfsPath)
	if err := vm.Start(); err != nil {
		return stream.Send(h.errorEvent(executionID, "VM_START_ERROR", err.Error()))
	}

	h.logger.Debug("VM started successfully", "executionID", executionID, "state", vm.State())

	// Set up timeout if specified
	var timeoutCh <-chan time.Time
	if timeout := execReq.GetTimeout(); timeout != nil && timeout.AsDuration() > 0 {
		timeoutCh = time.After(timeout.AsDuration())
	}

	// Wait for completion
	var exitCode int32 = 0
	var execErr error

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
		exitCode = result.exitCode
		if result.err != nil && exitCode == 0 {
			exitCode = 1
		}
		// Stop the VM now that command is done
		if vm.CanStop() {
			_ = vm.Stop()
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
		if err := stream.Send(h.errorEvent(executionID, "EXECUTION_ERROR", execErr.Error())); err != nil {
			return err
		}
	}

	// Send completed event
	duration := time.Since(startTime)
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

// executionResult holds the result of parsing VM output
type executionResult struct {
	exitCode int32
	err      error
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
	var outputBuf bytes.Buffer
	var allOutput bytes.Buffer
	inOutput := false
	isStderr := false
	buf := make([]byte, 4096)

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
			chunk := string(buf[:n])
			allOutput.WriteString(chunk)
			h.logger.Debug("RAW_READ", "bytes", n, "data", chunk)

			// Process line by line
			for _, line := range strings.Split(chunk, "\n") {
				line = strings.TrimRight(line, "\r")
				if line == "" {
					continue
				}

				// Check for protocol markers
				if strings.Contains(line, outputStartMarker) {
					inOutput = true
					isStderr = false
					continue
				}
				if strings.Contains(line, outputEndMarker) {
					if outputBuf.Len() > 0 {
						h.sendOutput(stream, executionID, outputBuf.Bytes(), isStderr)
						outputBuf.Reset()
					}
					inOutput = false
					continue
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
					done <- result
					return
				}
				if strings.Contains(line, stderrMarker) {
					if outputBuf.Len() > 0 && !isStderr {
						h.sendOutput(stream, executionID, outputBuf.Bytes(), false)
						outputBuf.Reset()
					}
					isStderr = true
					continue
				}
				if strings.Contains(line, stdoutMarker) {
					if outputBuf.Len() > 0 && isStderr {
						h.sendOutput(stream, executionID, outputBuf.Bytes(), true)
						outputBuf.Reset()
					}
					isStderr = false
					continue
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
			}
		}

		if err != nil {
			h.logger.Debug("parseVMOutput read error", "err", err, "totalOutput", allOutput.Len())
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
) (*vz.VirtualMachineConfiguration, error) {
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
	// Commands are space-separated (the init script uses eval to execute)
	command := req.GetCommand()
	cmdEncoded := base64.StdEncoding.EncodeToString([]byte(strings.Join(command, " ")))

	// Build kernel command line
	// The disk is always attached as /dev/vda.
	// We use init=/deputy-init which reads the command from the deputy.cmd parameter
	cmdline := fmt.Sprintf("console=hvc0 root=/dev/vda rw init=/deputy-init deputy.cmd=%s", cmdEncoded)

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
		return nil, fmt.Errorf("create bootloader: %w", err)
	}

	// Create VM configuration
	vmConfig, err := vz.NewVirtualMachineConfiguration(bootloader, cpuCount, memoryBytes)
	if err != nil {
		return nil, fmt.Errorf("create VM config: %w", err)
	}

	// Add serial console (for output streaming) using our pipes
	serialAttachment, err := vz.NewFileHandleSerialPortAttachment(stdinFile, stdoutFile)
	if err != nil {
		return nil, fmt.Errorf("create serial attachment: %w", err)
	}
	serialConfig, err := vz.NewVirtioConsoleDeviceSerialPortConfiguration(serialAttachment)
	if err != nil {
		return nil, fmt.Errorf("create serial config: %w", err)
	}
	vmConfig.SetSerialPortsVirtualMachineConfiguration([]*vz.VirtioConsoleDeviceSerialPortConfiguration{
		serialConfig,
	})

	// Add root disk
	diskAttachment, err := vz.NewDiskImageStorageDeviceAttachment(
		rootfsPath,
		config.GetMode() == sandboxv1.Mode_MODE_READ_ONLY, // read-only based on mode
	)
	if err != nil {
		return nil, fmt.Errorf("create disk attachment: %w", err)
	}

	blockDevice, err := vz.NewVirtioBlockDeviceConfiguration(diskAttachment)
	if err != nil {
		return nil, fmt.Errorf("create block device: %w", err)
	}
	vmConfig.SetStorageDevicesVirtualMachineConfiguration([]vz.StorageDeviceConfiguration{
		blockDevice,
	})

	// Add network based on network mode
	if config.GetNetworkMode() != sandboxv1.NetworkMode_NETWORK_MODE_NONE {
		natAttachment, err := vz.NewNATNetworkDeviceAttachment()
		if err != nil {
			return nil, fmt.Errorf("create NAT attachment: %w", err)
		}

		networkDevice, err := vz.NewVirtioNetworkDeviceConfiguration(natAttachment)
		if err != nil {
			return nil, fmt.Errorf("create network device: %w", err)
		}
		vmConfig.SetNetworkDevicesVirtualMachineConfiguration([]*vz.VirtioNetworkDeviceConfiguration{
			networkDevice,
		})
	}

	// Add entropy device for randomness
	entropyDevice, err := vz.NewVirtioEntropyDeviceConfiguration()
	if err != nil {
		return nil, fmt.Errorf("create entropy device: %w", err)
	}
	vmConfig.SetEntropyDevicesVirtualMachineConfiguration([]*vz.VirtioEntropyDeviceConfiguration{
		entropyDevice,
	})

	// Add memory balloon for dynamic memory
	balloonDevice, err := vz.NewVirtioTraditionalMemoryBalloonDeviceConfiguration()
	if err != nil {
		return nil, fmt.Errorf("create balloon device: %w", err)
	}
	vmConfig.SetMemoryBalloonDevicesVirtualMachineConfiguration([]vz.MemoryBalloonDeviceConfiguration{
		balloonDevice,
	})

	// Add workspace directory if specified (via virtio-fs or 9p)
	if workspaceDir := req.GetWorkspaceDir(); workspaceDir != "" {
		// Check for VirtioFileSystemDeviceConfiguration availability
		sharedDir, err := vz.NewSharedDirectory(workspaceDir, config.GetMode() == sandboxv1.Mode_MODE_READ_ONLY)
		if err != nil {
			h.logger.Warn("failed to create shared directory", "error", err)
		} else {
			shareConfig, err := vz.NewSingleDirectoryShare(sharedDir)
			if err != nil {
				h.logger.Warn("failed to create directory share", "error", err)
			} else {
				fsDevice, err := vz.NewVirtioFileSystemDeviceConfiguration("workspace")
				if err == nil {
					fsDevice.SetDirectoryShare(shareConfig)
					vmConfig.SetDirectorySharingDevicesVirtualMachineConfiguration([]vz.DirectorySharingDeviceConfiguration{
						fsDevice,
					})
				}
			}
		}
	}

	return vmConfig, nil
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
