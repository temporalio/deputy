package sandbox

import (
	"slices"
	"strings"
	"testing"
)

func TestFilterEnvVars(t *testing.T) {
	tests := []struct {
		name         string
		env          map[string]string
		wantFiltered map[string]string
		wantRemoved  []string
	}{
		{
			name: "pass through safe vars",
			env: map[string]string{
				"PATH": "/usr/bin",
				"HOME": "/home/user",
				"LANG": "en_US.UTF-8",
			},
			wantFiltered: map[string]string{
				"PATH": "/usr/bin",
				"HOME": "/home/user",
				"LANG": "en_US.UTF-8",
			},
			wantRemoved: nil,
		},
		{
			name: "filter LD_PRELOAD",
			env: map[string]string{
				"PATH":       "/usr/bin",
				"LD_PRELOAD": "/tmp/evil.so",
			},
			wantFiltered: map[string]string{
				"PATH": "/usr/bin",
			},
			wantRemoved: []string{"LD_PRELOAD"},
		},
		{
			name: "filter DYLD_INSERT_LIBRARIES",
			env: map[string]string{
				"PATH":                  "/usr/bin",
				"DYLD_INSERT_LIBRARIES": "/tmp/evil.dylib",
			},
			wantFiltered: map[string]string{
				"PATH": "/usr/bin",
			},
			wantRemoved: []string{"DYLD_INSERT_LIBRARIES"},
		},
		{
			name: "filter language injection vars",
			env: map[string]string{
				"PYTHONPATH":   "/tmp/python",
				"NODE_OPTIONS": "--experimental-modules",
				"RUBYOPT":      "-r/tmp/evil.rb",
			},
			wantFiltered: map[string]string{},
			wantRemoved:  []string{"PYTHONPATH", "NODE_OPTIONS", "RUBYOPT"},
		},
		{
			name: "filter credentials",
			env: map[string]string{
				"PATH":                  "/usr/bin",
				"AWS_SECRET_ACCESS_KEY": "secret",
				"GITHUB_TOKEN":          "ghp_xxxx",
				"ANTHROPIC_API_KEY":     "sk-ant-xxxx",
			},
			wantFiltered: map[string]string{
				"PATH": "/usr/bin",
			},
			wantRemoved: []string{"AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "ANTHROPIC_API_KEY"},
		},
		{
			name: "case insensitivity for blocked vars",
			env: map[string]string{
				"ld_preload": "/tmp/evil.so",
				"PATH":       "/usr/bin",
			},
			wantFiltered: map[string]string{
				"PATH": "/usr/bin",
			},
			wantRemoved: []string{"ld_preload"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			filtered, removed := FilterEnvVars(tc.env)

			// Check filtered matches expected
			if len(filtered) != len(tc.wantFiltered) {
				t.Errorf("filtered length = %d, want %d", len(filtered), len(tc.wantFiltered))
			}
			for k, wantV := range tc.wantFiltered {
				if gotV, ok := filtered[k]; !ok || gotV != wantV {
					t.Errorf("filtered[%q] = %q, want %q", k, gotV, wantV)
				}
			}

			// Check removed contains expected (order doesn't matter)
			if len(removed) != len(tc.wantRemoved) {
				t.Errorf("removed length = %d, want %d", len(removed), len(tc.wantRemoved))
			}
			for _, want := range tc.wantRemoved {
				found := false
				for _, got := range removed {
					if strings.EqualFold(got, want) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected %q in removed list", want)
				}
			}
		})
	}
}

func TestValidatePath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"empty path", "", false},
		{"current dir", ".", false},
		{"relative path", "relative/path", false},
		{"absolute tmp", "/tmp/test", false},
		{"absolute home", "/home/user/project", false},

		// Sensitive paths should be blocked
		{"etc passwd", "/etc/passwd", true},
		{"etc shadow", "/etc/shadow", true},
		{"etc sudoers", "/etc/sudoers", true},
		{"root home", "/root/something", true},
		{"proc 1", "/proc/1/environ", true},
		{"sys firmware", "/sys/firmware/efi", true},
		{"dev mem", "/dev/mem", true},
		{"dev kmem", "/dev/kmem", true},

		// Path traversal - note: relative traversal depends on cwd
		// The absolute path after resolution is what gets validated
		{"traversal with absolute", "/tmp/../etc/passwd", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePath(tc.path)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidatePath(%q) error = %v, wantErr = %v", tc.path, err, tc.wantErr)
			}
		})
	}
}

func TestValidateCommand(t *testing.T) {
	tests := []struct {
		name    string
		cmd     []string
		wantErr bool
	}{
		{"empty command", []string{}, true},
		{"normal ls", []string{"ls", "-la"}, false},
		{"normal echo", []string{"echo", "hello"}, false},
		{"git status", []string{"git", "status"}, false},
		{"npm install", []string{"npm", "install"}, false},
		{"go build", []string{"go", "build", "./..."}, false},

		// Dangerous binaries should be blocked (absolute paths)
		{"bin mount", []string{"/bin/mount", "/dev/sda1", "/mnt"}, true},
		{"sbin mount", []string{"/sbin/mount", "/dev/sda1", "/mnt"}, true},
		{"bin umount", []string{"/bin/umount", "/mnt"}, true},
		{"sbin umount", []string{"/sbin/umount", "/mnt"}, true},
		{"nsenter", []string{"/usr/bin/nsenter", "--target", "1"}, true},
		{"unshare", []string{"/usr/bin/unshare", "--mount"}, true},
		{"chroot", []string{"/usr/bin/chroot", "/newroot"}, true},
		{"pivot_root", []string{"/sbin/pivot_root", ".", "oldroot"}, true},

		// Dangerous binaries should also be blocked by name (PATH-resolved)
		{"mount bare", []string{"mount", "/dev/sda1", "/mnt"}, true},
		{"umount bare", []string{"umount", "/mnt"}, true},
		{"nsenter bare", []string{"nsenter", "--target", "1"}, true},
		{"unshare bare", []string{"unshare", "--mount"}, true},
		{"chroot bare", []string{"chroot", "/newroot"}, true},
		{"docker bare", []string{"docker", "run", "alpine"}, true},
		{"kubectl bare", []string{"kubectl", "exec", "-it", "pod"}, true},
		{"strace bare", []string{"strace", "-p", "1"}, true},
		{"gdb bare", []string{"gdb", "-p", "1"}, true},
		{"insmod bare", []string{"insmod", "module.ko"}, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateCommand(tc.cmd)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateCommand(%v) error = %v, wantErr = %v", tc.cmd, err, tc.wantErr)
			}
		})
	}
}

func TestGenerateExecutionID(t *testing.T) {
	// Test basic functionality
	id1 := GenerateExecutionID("test")
	if !strings.HasPrefix(id1, "test-") {
		t.Errorf("ID should start with prefix: %s", id1)
	}

	// Test uniqueness
	ids := make(map[string]bool)
	for range 1000 {
		id := GenerateExecutionID("prefix")
		if ids[id] {
			t.Errorf("Generated duplicate ID: %s", id)
		}
		ids[id] = true
	}

	// Test with empty prefix
	emptyID := GenerateExecutionID("")
	if emptyID == "" {
		t.Error("ID should not be empty even with empty prefix")
	}
}

func TestMinimalCapabilities(t *testing.T) {
	caps := MinimalCapabilities()
	if len(caps) == 0 {
		t.Error("MinimalCapabilities should return at least some capabilities")
	}

	// Verify dangerous capabilities are not included
	for _, cap := range caps {
		for _, dangerous := range DangerousCapabilities {
			if cap == dangerous {
				t.Errorf("MinimalCapabilities includes dangerous capability: %s", cap)
			}
		}
	}
}

func TestDefaultCapabilities(t *testing.T) {
	caps := DefaultCapabilities()
	if len(caps) == 0 {
		t.Error("DefaultCapabilities should return at least some capabilities")
	}

	// Verify dangerous capabilities are not included
	for _, cap := range caps {
		for _, dangerous := range DangerousCapabilities {
			if cap == dangerous {
				t.Errorf("DefaultCapabilities includes dangerous capability: %s", cap)
			}
		}
	}
}

func TestResourceDefaults(t *testing.T) {
	defaults := DefaultResourceLimits()
	if defaults.MemoryLimit == "" {
		t.Error("DefaultResourceLimits should set memory limit")
	}
	if defaults.CPULimit == "" {
		t.Error("DefaultResourceLimits should set CPU limit")
	}
	if defaults.MaxPIDs == 0 {
		t.Error("DefaultResourceLimits should set max PIDs")
	}

	strict := StrictResourceLimits()
	if strict.MaxPIDs >= defaults.MaxPIDs {
		t.Error("StrictResourceLimits should have lower MaxPIDs than default")
	}
}

func TestBlockedEnvVarsCompleteness(t *testing.T) {
	// Ensure all major injection vectors are covered
	requiredBlocked := []string{
		// Dynamic linker
		"LD_PRELOAD",
		"LD_LIBRARY_PATH",
		"DYLD_INSERT_LIBRARIES",

		// Language code injection
		"PYTHONPATH",
		"NODE_OPTIONS",
		"RUBYOPT",
		"JAVA_TOOL_OPTIONS",

		// Shell injection
		"BASH_ENV",
		"PROMPT_COMMAND",

		// Credential leakage
		"AWS_SECRET_ACCESS_KEY",
		"GITHUB_TOKEN",
		"ANTHROPIC_API_KEY",
	}

	for _, required := range requiredBlocked {
		if !BlockedEnvVars[required] {
			t.Errorf("BlockedEnvVars should include %q", required)
		}
	}
}

func TestDangerousCapabilitiesCompleteness(t *testing.T) {
	// Ensure the most dangerous capabilities are blocked
	requiredDangerous := []string{
		"CAP_SYS_ADMIN",
		"CAP_SYS_PTRACE",
		"CAP_SYS_MODULE",
		"CAP_SYS_RAWIO",
	}

	for _, required := range requiredDangerous {
		found := slices.Contains(DangerousCapabilities, required)
		if !found {
			t.Errorf("DangerousCapabilities should include %q", required)
		}
	}
}
