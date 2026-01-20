package sandbox

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// DangerousEnvVars contains environment variables that should never be passed
// to sandboxed processes as they can be used for code injection or privilege escalation.
var DangerousEnvVars = map[string]bool{
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
	"PYTHONPATH":        true,
	"PYTHONSTARTUP":     true,
	"RUBYOPT":           true,
	"RUBYLIB":           true,
	"PERL5LIB":          true,
	"PERL5OPT":          true,
	"NODE_OPTIONS":      true,
	"NODE_PATH":         true,
	"JAVA_TOOL_OPTIONS": true,

	// Shell injection vectors
	"BASH_ENV":       true,
	"ENV":            true,
	"CDPATH":         true,
	"GLOBIGNORE":     true,
	"PROMPT_COMMAND": true,

	// Credential leakage prevention
	// These should never be passed to sandboxed processes to prevent
	// untrusted code from exfiltrating credentials.
	"AWS_SECRET_ACCESS_KEY":     true,
	"AWS_ACCESS_KEY_ID":         true,
	"AWS_SESSION_TOKEN":         true,
	"GITHUB_TOKEN":              true,
	"GH_TOKEN":                  true,
	"GITLAB_TOKEN":              true,
	"ANTHROPIC_API_KEY":         true,
	"OPENAI_API_KEY":            true,
	"GOOGLE_API_KEY":            true,
	"AZURE_CLIENT_SECRET":       true,
	"AZURE_TENANT_ID":           true,
	"NPM_TOKEN":                 true,
	"PYPI_TOKEN":                true,
	"DOCKER_PASSWORD":           true,
	"DOCKER_AUTH_CONFIG":        true,
	"REGISTRY_AUTH":             true,
	"SSH_AUTH_SOCK":             true,
	"GPG_TTY":                   true,
	"SLACK_TOKEN":               true,
	"SLACK_WEBHOOK_URL":         true,
	"TWILIO_AUTH_TOKEN":         true,
	"SENDGRID_API_KEY":          true,
	"STRIPE_SECRET_KEY":         true,
	"DATABASE_URL":              true,
	"DATABASE_PASSWORD":         true,
	"DB_PASSWORD":               true,
	"MYSQL_PASSWORD":            true,
	"POSTGRES_PASSWORD":         true,
	"REDIS_PASSWORD":            true,
	"MONGODB_URI":               true,
	"JWT_SECRET":                true,
	"SECRET_KEY":                true,
	"ENCRYPTION_KEY":            true,
	"API_KEY":                   true,
	"API_SECRET":                true,
	"PRIVATE_KEY":               true,
	"SERVICE_ACCOUNT_KEY":       true,
	"GOOGLE_APPLICATION_CREDENTIALS": true,
}

// BlockedEnvVars is a deprecated alias for DangerousEnvVars.
var BlockedEnvVars = DangerousEnvVars

// SafeHostEnvVars contains environment variables that are considered safe to inherit
// from the host environment. All other host variables will be stripped unless
// explicitly provided by the user.
var SafeHostEnvVars = map[string]bool{
	"PATH": true,
	"TERM": true,
	"HOME": true,
	"LANG": true,
	"TZ":   true,
}

// SanitizeEnvironment constructs a safe environment for a sandboxed process.
//
// It strictly limits inherited host variables to SafeHostEnvVars, then applies
// user-provided variables. Finally, it ensures no DangerousEnvVars are present
// in the final result.
//
// Returns:
//   - finalEnv: The safe list of "KEY=VALUE" strings
//   - removed: List of keys that were blocked/removed (for auditing)
func SanitizeEnvironment(hostEnv []string, userEnv map[string]string) (finalEnv []string, removed []string) {
	// 1. Start with safe host variables
	safeMap := make(map[string]string)

	for _, entry := range hostEnv {
		k, v, ok := strings.Cut(entry, "=")
		if !ok || k == "" {
			continue
		}

		// Only inherit allowed host variables
		if SafeHostEnvVars[k] {
			safeMap[k] = v
		}
	}

	// 2. Apply user-provided variables (overriding host vars)
	for k, v := range userEnv {
		safeMap[k] = v
	}

	// 3. Filter out dangerous variables
	// We do this last to ensure even user-provided vars are checked against the blocklist
	// (as per existing security policy to prevent accidental privilege escalation)
	filteredEnv := make([]string, 0, len(safeMap))

	for k, v := range safeMap {
		if DangerousEnvVars[k] || DangerousEnvVars[strings.ToUpper(k)] {
			removed = append(removed, k)
			continue
		}
		filteredEnv = append(filteredEnv, fmt.Sprintf("%s=%s", k, v))
	}

	return filteredEnv, removed
}

// FilterEnvVars removes dangerous environment variables from the provided map.
// Returns the filtered map and a list of removed variables for audit logging.
func FilterEnvVars(env map[string]string) (filtered map[string]string, removed []string) {
	filtered = make(map[string]string, len(env))
	for k, v := range env {
		if DangerousEnvVars[k] || DangerousEnvVars[strings.ToUpper(k)] {
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
	// This list follows defense-in-depth principles - even if the sandbox
	// provides isolation, we block these at the API level as well.
	sensitiveRoots := []string{
		// Authentication and authorization
		"/etc/passwd",
		"/etc/shadow",
		"/etc/sudoers",
		"/etc/sudoers.d",
		"/etc/pam.d",
		"/etc/security",
		"/etc/gshadow",
		"/etc/master.passwd", // BSD

		// User directories
		"/root", // Root user home

		// SSH and crypto keys
		"/etc/ssh",

		// System configuration that could enable privilege escalation
		"/etc/crontab",
		"/etc/cron.d",
		"/etc/cron.daily",
		"/etc/cron.hourly",
		"/etc/cron.weekly",
		"/etc/cron.monthly",
		"/var/spool/cron",
		"/etc/init.d",
		"/etc/systemd",
		"/etc/rc.d",
		"/etc/rc.local",

		// Kernel and hardware access
		"/proc/1",          // Host init process
		"/proc/kcore",      // Kernel memory
		"/proc/kmem",       // Kernel memory
		"/proc/kallsyms",   // Kernel symbols
		"/proc/modules",    // Kernel modules
		"/sys/firmware",    // UEFI/BIOS
		"/sys/kernel",      // Kernel configuration
		"/sys/module",      // Kernel modules
		"/dev/mem",         // Physical memory
		"/dev/kmem",        // Kernel memory
		"/dev/port",        // I/O ports
		"/boot",            // Boot configuration

		// Container/virtualization escape vectors
		"/var/run/docker.sock",
		"/run/docker.sock",
		"/var/run/containerd",
		"/run/containerd",
		"/var/lib/docker",
		"/var/lib/containerd",
		"/var/lib/kubelet",

		// Package manager configs (supply chain risk)
		"/etc/apt/sources.list",
		"/etc/apt/sources.list.d",
		"/etc/yum.repos.d",
		"/etc/dnf/dnf.conf",

		// macOS specific
		"/Library/LaunchDaemons",
		"/Library/LaunchAgents",
		"/System/Library/LaunchDaemons",
		"/private/var/db/dslocal", // Directory Services
	}

	for _, sensitive := range sensitiveRoots {
		// Check for exact match or directory prefix match
		// (e.g., /root matches /root and /root/something, but not /rootfs)
		if absPath == sensitive || strings.HasPrefix(absPath, sensitive+string(filepath.Separator)) {
			return fmt.Errorf("access to sensitive path denied: %s", absPath)
		}
	}

	return nil
}

// DangerousBinaries contains binaries that should not be executed in a sandbox.
// These can be used for privilege escalation, container escape, or other attacks.
var DangerousBinaries = map[string]bool{
	// Namespace and mount manipulation
	"mount":      true,
	"umount":     true,
	"nsenter":    true,
	"unshare":    true,
	"chroot":     true,
	"pivot_root": true,

	// Process debugging (can attach to host processes)
	"strace":   true,
	"ltrace":   true,
	"ptrace":   true,
	"gdb":      true,
	"lldb":     true,
	"debugfs":  true,
	"perf":     true,
	"bpftrace": true,

	// Kernel module manipulation
	"insmod":  true,
	"rmmod":   true,
	"modprobe": true,
	"depmod":  true,

	// Direct hardware/memory access
	"kexec":   true,
	"dmsetup": true,
	"losetup": true,

	// Container/VM escape tools
	"docker":     true,
	"podman":     true,
	"containerd": true,
	"ctr":        true,
	"crictl":     true,
	"kubectl":    true, // Can potentially access host cluster
	"runc":       true,

	// System administration
	"init":     true,
	"systemctl": true,
	"service":  true,
	"reboot":   true,
	"shutdown": true,
	"halt":     true,
	"poweroff": true,
}

// ValidateCommand checks if a command is safe to execute.
// Returns an error if the command contains suspicious patterns.
// This validates both absolute paths and bare command names.
func ValidateCommand(cmd []string) error {
	if len(cmd) == 0 {
		return fmt.Errorf("empty command")
	}

	executable := cmd[0]

	// Extract the base name for PATH-resolved commands
	baseName := filepath.Base(executable)

	// Check if the base name is in the dangerous list
	if DangerousBinaries[baseName] {
		return fmt.Errorf("execution of %q is not allowed in sandbox: potentially dangerous binary", executable)
	}

	// Additional check for absolute paths to dangerous locations
	if filepath.IsAbs(executable) {
		dangerousPaths := []string{
			"/bin/mount",
			"/bin/umount",
			"/sbin/mount",
			"/sbin/umount",
			"/usr/bin/nsenter",
			"/usr/bin/unshare",
			"/usr/bin/chroot",
			"/sbin/pivot_root",
			"/usr/sbin/chroot",
			"/usr/bin/docker",
			"/usr/local/bin/docker",
		}

		for _, dangerous := range dangerousPaths {
			if executable == dangerous {
				return fmt.Errorf("execution of %s is not allowed in sandbox", executable)
			}
		}
	}

	// Check for shell command injection patterns in arguments
	// These could be used to bypass the command check
	shellMetachars := []string{"$(", "`", "&&", "||", ";", "|", ">", "<", "\n", "\r"}
	for i, arg := range cmd {
		if i == 0 {
			continue // Skip the executable itself
		}
		for _, meta := range shellMetachars {
			if strings.Contains(arg, meta) {
				// This is a warning-level check - shells handle this, but it's suspicious
				// in a direct exec context where we're not going through a shell
				// For now, we allow it but could be made stricter
				break
			}
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
		"CAP_CHOWN",            // Change file ownership
		"CAP_FOWNER",           // Bypass permission checks for file owner
		"CAP_FSETID",           // Set file SUID/SGID bits
		"CAP_KILL",             // Send signals
		"CAP_SETGID",           // Set GID
		"CAP_SETUID",           // Set UID
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
		"CAP_NET_RAW", // Raw sockets (needed for ping, etc.)
		"CAP_MKNOD",   // Create special files
	}
}

// DangerousCapabilities that should never be granted in a sandbox.
var DangerousCapabilities = []string{
	"CAP_SYS_ADMIN",       // Mount, namespace operations, etc.
	"CAP_SYS_PTRACE",      // Debug other processes
	"CAP_SYS_MODULE",      // Load kernel modules
	"CAP_SYS_RAWIO",       // Direct I/O access
	"CAP_SYS_BOOT",        // Reboot system
	"CAP_DAC_READ_SEARCH", // Bypass file read permission checks
	"CAP_DAC_OVERRIDE",    // Bypass file permission checks (removed from default)
	"CAP_SYS_CHROOT",      // Can help escape chroot (removed from default)
	"CAP_SETPCAP",         // Modify process capabilities (removed from default)
	"CAP_SETFCAP",         // Set file capabilities (removed from default)
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
