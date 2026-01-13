// Copyright 2024 Deputy Authors
// SPDX-License-Identifier: Apache-2.0

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
	"context"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"connectrpc.com/connect"
	"github.com/Code-Hex/vz/v3"
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

	slog.Info("vz sandbox plugin listening", "socket", *socketPath)
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
	kernelPath, rootfsPath, initrdPath, err := h.resolveAssetPaths()
	if err != nil {
		return stream.Send(h.errorEvent(executionID, "ASSET_ERROR", err.Error()))
	}

	// Create VM configuration
	vmConfig, err := h.createVMConfig(execReq, kernelPath, rootfsPath, initrdPath)
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

	// Start the VM
	if err := vm.Start(); err != nil {
		return stream.Send(h.errorEvent(executionID, "VM_START_ERROR", err.Error()))
	}

	// Wait for VM to complete or context cancellation
	startTime := time.Now()
	var exitCode int32 = 0

	// Monitor VM state
	select {
	case <-vmCtx.Done():
		// Context cancelled, stop VM
		if vm.CanStop() {
			_ = vm.Stop()
		}
		exitCode = 137 // Killed
	case state := <-waitForVMState(vm):
		switch state {
		case vz.VirtualMachineStateStopped:
			exitCode = 0
		case vz.VirtualMachineStateError:
			exitCode = 1
		default:
			exitCode = 0
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

func (h *vzHandler) resolveAssetPaths() (kernel, rootfs, initrd string, err error) {
	// Check environment variables first
	kernel = os.Getenv(envKernelPath)
	rootfs = os.Getenv(envRootfsPath)
	initrd = os.Getenv(envInitrdPath)

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
	if initrd == "" {
		initrd = filepath.Join(assetDir, "initrd.img")
	}

	// Validate kernel exists
	if _, err := os.Stat(kernel); os.IsNotExist(err) {
		return "", "", "", fmt.Errorf("kernel not found at %s (set %s)", kernel, envKernelPath)
	}

	// Validate rootfs exists
	if _, err := os.Stat(rootfs); os.IsNotExist(err) {
		return "", "", "", fmt.Errorf("rootfs not found at %s (set %s)", rootfs, envRootfsPath)
	}

	// Initrd is optional
	if _, err := os.Stat(initrd); os.IsNotExist(err) {
		initrd = "" // Optional, clear if not found
	}

	return kernel, rootfs, initrd, nil
}

func (h *vzHandler) createVMConfig(
	req *sandboxv1.RuntimeExecuteRequest,
	kernelPath, rootfsPath, initrdPath string,
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

	// Build kernel command line
	// The disk is always attached as /dev/vda. The initramfs will find and mount it.
	// We use init=/bin/bash to skip systemd/cloud-init and boot directly to a shell.
	cmdline := "console=hvc0 root=/dev/vda rw init=/bin/bash"

	// Add quiet boot unless debug logging is enabled
	if os.Getenv("DEPUTY_LOG_LEVEL") != "debug" {
		cmdline += " quiet loglevel=3"
	} else {
		// Show boot messages for debugging
		cmdline += " loglevel=7"
	}

	// Create bootloader with optional initrd
	bootloaderOpts := []vz.LinuxBootLoaderOption{vz.WithCommandLine(cmdline)}
	if initrdPath != "" {
		bootloaderOpts = append(bootloaderOpts, vz.WithInitrd(initrdPath))
	}

	bootloader, err := vz.NewLinuxBootLoader(kernelPath, bootloaderOpts...)
	if err != nil {
		return nil, fmt.Errorf("create bootloader: %w", err)
	}

	// Create VM configuration
	vmConfig, err := vz.NewVirtualMachineConfiguration(bootloader, cpuCount, memoryBytes)
	if err != nil {
		return nil, fmt.Errorf("create VM config: %w", err)
	}

	// Add serial console (for output streaming)
	serialAttachment, err := vz.NewFileHandleSerialPortAttachment(os.Stdin, os.Stdout)
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
