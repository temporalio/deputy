//go:build ignore

// Simple test to verify VM boots with Ubuntu assets
// Run with: go run simple_vm_test.go

package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Code-Hex/vz/v3"
	"github.com/creack/pty"
)

func main() {
	homeDir, _ := os.UserHomeDir()
	assetDir := filepath.Join(homeDir, ".deputy/vz")

	kernelPath := filepath.Join(assetDir, "vmlinuz")
	rootfsPath := filepath.Join(assetDir, "rootfs.img")
	initrdPath := filepath.Join(assetDir, "initrd.img")

	fmt.Printf("Kernel: %s\n", kernelPath)
	fmt.Printf("Rootfs: %s\n", rootfsPath)
	fmt.Printf("Initrd: %s\n", initrdPath)

	// Create PTY for console
	ptyMaster, ptySlave, err := pty.Open()
	if err != nil {
		fmt.Printf("Failed to create PTY: %v\n", err)
		os.Exit(1)
	}
	defer ptyMaster.Close()
	defer ptySlave.Close()

	// Test command - space separated (simpler than null bytes for shell parsing)
	testCmd := "uname -a"
	cmdEncoded := base64.StdEncoding.EncodeToString([]byte(testCmd))

	// Kernel cmdline - run deputy-init directly without initrd
	cmdline := fmt.Sprintf("console=hvc0 root=/dev/vda rw init=/deputy-init deputy.cmd=%s", cmdEncoded)

	fmt.Printf("Cmdline: %s\n", cmdline)

	// Create bootloader WITHOUT initrd - boot directly to rootfs
	bootloader, err := vz.NewLinuxBootLoader(
		kernelPath,
		vz.WithCommandLine(cmdline),
		// vz.WithInitrd(initrdPath),  // Skipping initrd - kernel mounts rootfs directly
	)
	if err != nil {
		fmt.Printf("Failed to create bootloader: %v\n", err)
		os.Exit(1)
	}

	// Create VM config: 1 CPU, 1GB RAM
	vmConfig, err := vz.NewVirtualMachineConfiguration(bootloader, 1, 1024*1024*1024)
	if err != nil {
		fmt.Printf("Failed to create VM config: %v\n", err)
		os.Exit(1)
	}

	// Add serial console
	serialAttachment, err := vz.NewFileHandleSerialPortAttachment(ptySlave, ptySlave)
	if err != nil {
		fmt.Printf("Failed to create serial attachment: %v\n", err)
		os.Exit(1)
	}
	serialConfig, err := vz.NewVirtioConsoleDeviceSerialPortConfiguration(serialAttachment)
	if err != nil {
		fmt.Printf("Failed to create serial config: %v\n", err)
		os.Exit(1)
	}
	vmConfig.SetSerialPortsVirtualMachineConfiguration([]*vz.VirtioConsoleDeviceSerialPortConfiguration{
		serialConfig,
	})

	// Add disk
	diskAttachment, err := vz.NewDiskImageStorageDeviceAttachment(rootfsPath, false)
	if err != nil {
		fmt.Printf("Failed to create disk attachment: %v\n", err)
		os.Exit(1)
	}
	diskConfig, err := vz.NewVirtioBlockDeviceConfiguration(diskAttachment)
	if err != nil {
		fmt.Printf("Failed to create disk config: %v\n", err)
		os.Exit(1)
	}
	vmConfig.SetStorageDevicesVirtualMachineConfiguration([]vz.StorageDeviceConfiguration{
		diskConfig,
	})

	// Add entropy device
	entropyConfig, err := vz.NewVirtioEntropyDeviceConfiguration()
	if err != nil {
		fmt.Printf("Failed to create entropy config: %v\n", err)
		os.Exit(1)
	}
	vmConfig.SetEntropyDevicesVirtualMachineConfiguration([]*vz.VirtioEntropyDeviceConfiguration{
		entropyConfig,
	})

	// Validate
	validated, err := vmConfig.Validate()
	if err != nil {
		fmt.Printf("Validation error: %v\n", err)
		os.Exit(1)
	}
	if !validated {
		fmt.Println("Validation failed")
		os.Exit(1)
	}

	// Create VM
	vm, err := vz.NewVirtualMachine(vmConfig)
	if err != nil {
		fmt.Printf("Failed to create VM: %v\n", err)
		os.Exit(1)
	}

	// Read output in goroutine
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := ptyMaster.Read(buf)
			if n > 0 {
				fmt.Print(string(buf[:n]))
			}
			if err != nil {
				fmt.Printf("\n[PTY read error: %v]\n", err)
				return
			}
		}
	}()

	// Handle Ctrl-C
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\n[Stopping VM...]")
		if vm.CanStop() {
			vm.Stop()
		}
		os.Exit(0)
	}()

	// Start VM
	fmt.Println("Starting VM...")
	if err := vm.Start(); err != nil {
		fmt.Printf("Failed to start VM: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("VM started, state: %v\n", vm.State())

	// Wait for completion or timeout
	timeout := time.After(60 * time.Second)
	for {
		select {
		case <-timeout:
			fmt.Println("\n[Timeout reached, stopping VM]")
			if vm.CanStop() {
				vm.Stop()
			}
			return
		default:
			time.Sleep(100 * time.Millisecond)
			state := vm.State()
			if state == vz.VirtualMachineStateStopped || state == vz.VirtualMachineStateError {
				fmt.Printf("\n[VM stopped/error, state: %v]\n", state)
				return
			}
		}
	}
}
