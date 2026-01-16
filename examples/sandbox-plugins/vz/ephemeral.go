//go:build darwin && arm64

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// ephemeralRootfs manages ephemeral copies of the rootfs for isolated execution.
// On APFS filesystems, it uses clonefile for instant copy-on-write clones.
// The ephemeral copy is automatically cleaned up after execution.
type ephemeralRootfs struct {
	basePath      string // Path to the base rootfs.img
	ephemeralPath string // Path to the ephemeral clone
	tempDir       string // Temporary directory holding the clone
}

// newEphemeralRootfs creates an ephemeral copy of the rootfs using APFS clonefile.
// The clone shares storage with the base image until modified (copy-on-write).
// This is instant (~1ms) regardless of rootfs size.
func newEphemeralRootfs(basePath string) (*ephemeralRootfs, error) {
	// Verify base rootfs exists
	if _, err := os.Stat(basePath); err != nil {
		return nil, fmt.Errorf("base rootfs not found: %w", err)
	}

	// Create temp directory for ephemeral images
	// Using a unique name with timestamp and PID for parallel execution safety
	tempDir := filepath.Join(filepath.Dir(basePath), ".ephemeral",
		fmt.Sprintf("exec-%d-%d", time.Now().UnixNano(), os.Getpid()))
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		return nil, fmt.Errorf("create temp directory: %w", err)
	}

	ephemeralPath := filepath.Join(tempDir, "rootfs.img")

	// Try APFS clonefile first (instant copy-on-write)
	err := clonefile(basePath, ephemeralPath)
	if err != nil {
		// Fall back to regular copy if clonefile fails (non-APFS filesystem)
		// This is slower but works on all filesystems
		if copyErr := copyFile(basePath, ephemeralPath); copyErr != nil {
			os.RemoveAll(tempDir)
			return nil, fmt.Errorf("create ephemeral rootfs: clonefile failed (%v), copy failed (%v)", err, copyErr)
		}
	}

	return &ephemeralRootfs{
		basePath:      basePath,
		ephemeralPath: ephemeralPath,
		tempDir:       tempDir,
	}, nil
}

// Path returns the path to the ephemeral rootfs image.
func (e *ephemeralRootfs) Path() string {
	return e.ephemeralPath
}

// Cleanup removes the ephemeral rootfs and its directory.
// Safe to call multiple times.
func (e *ephemeralRootfs) Cleanup() error {
	if e.tempDir != "" {
		return os.RemoveAll(e.tempDir)
	}
	return nil
}

// clonefile creates a copy-on-write clone using APFS clonefile syscall.
// This is instant regardless of file size on APFS filesystems.
func clonefile(src, dst string) error {
	// The clonefile syscall creates an APFS clone (copy-on-write copy)
	// Flags: 0 = default (fail if dst exists)
	return unix.Clonefile(src, dst, 0)
}

// copyFile creates a regular copy of a file (fallback for non-APFS).
func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	srcInfo, err := srcFile.Stat()
	if err != nil {
		return err
	}

	dstFile, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, srcInfo.Mode())
	if err != nil {
		return err
	}
	defer dstFile.Close()

	// Use sendfile for efficient kernel-level copy
	srcFd := int(srcFile.Fd())
	dstFd := int(dstFile.Fd())
	size := srcInfo.Size()

	for size > 0 {
		// sendfile on Darwin: dst, src, offset, len
		// offset nil = use current file position
		written, err := syscall.Sendfile(dstFd, srcFd, nil, int(size))
		if err != nil {
			return fmt.Errorf("sendfile: %w", err)
		}
		if written == 0 {
			break
		}
		size -= int64(written)
	}

	return nil
}
