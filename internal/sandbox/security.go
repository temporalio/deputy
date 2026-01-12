// Copyright 2024 Deputy Authors
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// BlockedEnvVars contains environment variables that should never be passed
// to sandboxed processes as they can be used for code injection or privilege escalation.
var BlockedEnvVars = map[string]bool{
	// Dynamic linker injection
	"LD_PRELOAD":      true,
	"LD_LIBRARY_PATH": true,
	"LD_AUDIT":        true,
	"LD_DEBUG":        true,
	"LD_PROFILE":      true,

	// macOS dynamic linker
	"DYLD_INSERT_LIBRARIES": true,
	"DYLD_LIBRARY_PATH":     true,
	"DYLD_FRAMEWORK_PATH":   true,

	// Language-specific code injection
	"PYTHONPATH":      true,
	"PYTHONSTARTUP":   true,
	"RUBYOPT":         true,
	"RUBYLIB":         true,
	"PERL5LIB":        true,
	"PERL5OPT":        true,
	"NODE_OPTIONS":    true,
	"NODE_PATH":       true,
	"JAVA_TOOL_OPTIONS": true,

	// Shell injection vectors
	"BASH_ENV":    true,
	"ENV":         true,
	"CDPATH":      true,
	"GLOBIGNORE":  true,
	"PROMPT_COMMAND": true,

	// Credential/token leakage prevention
	"AWS_SECRET_ACCESS_KEY": true,
	"AWS_SESSION_TOKEN":     true,
	"GITHUB_TOKEN":          true,
	"GH_TOKEN":              true,
	"ANTHROPIC_API_KEY":     true,
	"OPENAI_API_KEY":        true,
}

// FilterEnvVars removes dangerous environment variables from the provided map.
// Returns the filtered map and a list of removed variables for audit logging.
func FilterEnvVars(env map[string]string) (filtered map[string]string, removed []string) {
	filtered = make(map[string]string, len(env))
	for k, v := range env {
		if BlockedEnvVars[k] || BlockedEnvVars[strings.ToUpper(k)] {
			removed = append(removed, k)
			continue
		}
		filtered[k] = v
	}
	return filtered, removed
}

// ValidatePath checks if a path is safe for use in sandbox operations.
// It returns an error if the path contains suspicious patterns.
func ValidatePath(path string) error {
	if path == "" {
		return nil
	}

	// Resolve to absolute path
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}

	// Check for path traversal attempts
	if strings.Contains(path, "..") {
		// Verify the resolved path doesn't escape expected boundaries
		cleanPath := filepath.Clean(absPath)
		if cleanPath != absPath {
			return fmt.Errorf("path traversal detected: %s resolves to %s", path, cleanPath)
		}
	}

	// Block access to sensitive system paths
	sensitiveRoots := []string{
		"/etc/passwd",
		"/etc/shadow",
		"/etc/sudoers",
		"/root",
		"/proc/1",        // Host init process
		"/sys/firmware",  // UEFI/BIOS
		"/dev/mem",       // Physical memory
		"/dev/kmem",      // Kernel memory
	}

	for _, sensitive := range sensitiveRoots {
		if strings.HasPrefix(absPath, sensitive) {
			return fmt.Errorf("access to sensitive path denied: %s", absPath)
		}
	}

	return nil
}

// ValidateCommand checks if a command is safe to execute.
// Returns an error if the command contains suspicious patterns.
func ValidateCommand(cmd []string) error {
	if len(cmd) == 0 {
		return fmt.Errorf("empty command")
	}

	executable := cmd[0]

	// Block absolute paths to sensitive binaries when executed directly
	dangerousBinaries := []string{
		"/bin/mount",
		"/bin/umount",
		"/sbin/mount",
		"/sbin/umount",
		"/usr/bin/nsenter",
		"/usr/bin/unshare",
		"/usr/bin/chroot",
		"/sbin/pivot_root",
	}

	for _, dangerous := range dangerousBinaries {
		if executable == dangerous {
			return fmt.Errorf("execution of %s is not allowed in sandbox", executable)
		}
	}

	return nil
}

// GenerateExecutionID creates a cryptographically random execution ID.
// This prevents prediction attacks on container IDs.
func GenerateExecutionID(prefix string) string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fallback to timestamp-based ID (still unique, less random)
		return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
	}
	return fmt.Sprintf("%s-%s", prefix, hex.EncodeToString(b))
}

// MinimalCapabilities returns a minimal set of Linux capabilities
// suitable for most sandboxed workloads.
func MinimalCapabilities() []string {
	return []string{
		"CAP_CHOWN",           // Change file ownership
		"CAP_FOWNER",          // Bypass permission checks for file owner
		"CAP_FSETID",          // Set file SUID/SGID bits
		"CAP_KILL",            // Send signals
		"CAP_SETGID",          // Set GID
		"CAP_SETUID",          // Set UID
		"CAP_NET_BIND_SERVICE", // Bind to ports < 1024
	}
}

// DefaultCapabilities returns the default set of Linux capabilities.
// This is more permissive than MinimalCapabilities but still removes
// the most dangerous ones.
func DefaultCapabilities() []string {
	return []string{
		"CAP_CHOWN",
		"CAP_FOWNER",
		"CAP_FSETID",
		"CAP_KILL",
		"CAP_SETGID",
		"CAP_SETUID",
		"CAP_NET_BIND_SERVICE",
		"CAP_NET_RAW",  // Raw sockets (needed for ping, etc.)
		"CAP_MKNOD",    // Create special files
	}
}

// DangerousCapabilities that should never be granted in a sandbox.
var DangerousCapabilities = []string{
	"CAP_SYS_ADMIN",    // Mount, namespace operations, etc.
	"CAP_SYS_PTRACE",   // Debug other processes
	"CAP_SYS_MODULE",   // Load kernel modules
	"CAP_SYS_RAWIO",    // Direct I/O access
	"CAP_SYS_BOOT",     // Reboot system
	"CAP_DAC_READ_SEARCH", // Bypass file read permission checks
	"CAP_DAC_OVERRIDE", // Bypass file permission checks (removed from default)
	"CAP_SYS_CHROOT",   // Can help escape chroot (removed from default)
	"CAP_SETPCAP",      // Modify process capabilities (removed from default)
	"CAP_SETFCAP",      // Set file capabilities (removed from default)
}

// ResourceDefaults provides sensible default resource limits.
type ResourceDefaults struct {
	// MemoryLimit is the default memory limit (e.g., "512m", "1g")
	MemoryLimit string

	// CPULimit is the default CPU limit (e.g., "1.0", "0.5")
	CPULimit string

	// MaxPIDs is the maximum number of processes
	MaxPIDs int32

	// MaxOpenFiles is the maximum number of open file descriptors
	MaxOpenFiles int32

	// MaxFileSizeBytes is the maximum file size that can be created
	MaxFileSizeBytes int64
}

// DefaultResourceLimits returns conservative default resource limits.
func DefaultResourceLimits() ResourceDefaults {
	return ResourceDefaults{
		MemoryLimit:      "512m",
		CPULimit:         "1.0",
		MaxPIDs:          256,
		MaxOpenFiles:     1024,
		MaxFileSizeBytes: 100 * 1024 * 1024, // 100MB
	}
}

// StrictResourceLimits returns strict resource limits for untrusted code.
func StrictResourceLimits() ResourceDefaults {
	return ResourceDefaults{
		MemoryLimit:      "256m",
		CPULimit:         "0.5",
		MaxPIDs:          64,
		MaxOpenFiles:     256,
		MaxFileSizeBytes: 10 * 1024 * 1024, // 10MB
	}
}
