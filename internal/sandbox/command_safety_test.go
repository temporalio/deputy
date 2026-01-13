package sandbox

import "testing"

func TestClassifyCommand(t *testing.T) {
	tests := []struct {
		name     string
		cmd      []string
		expected CommandSafety
	}{
		// Safe commands
		{name: "ls", cmd: []string{"ls", "-la"}, expected: CommandSafe},
		{name: "cat", cmd: []string{"cat", "file.txt"}, expected: CommandSafe},
		{name: "grep", cmd: []string{"grep", "pattern", "file"}, expected: CommandSafe},
		{name: "head", cmd: []string{"head", "-n", "10", "file"}, expected: CommandSafe},
		{name: "tail", cmd: []string{"tail", "-f", "log.txt"}, expected: CommandSafe},
		{name: "pwd", cmd: []string{"pwd"}, expected: CommandSafe},
		{name: "whoami", cmd: []string{"whoami"}, expected: CommandSafe},
		{name: "echo", cmd: []string{"echo", "hello"}, expected: CommandSafe},
		{name: "wc", cmd: []string{"wc", "-l", "file.txt"}, expected: CommandSafe},
		{name: "diff", cmd: []string{"diff", "file1", "file2"}, expected: CommandSafe},

		// Conditionally safe - git
		{name: "git status", cmd: []string{"git", "status"}, expected: CommandSafe},
		{name: "git log", cmd: []string{"git", "log", "--oneline"}, expected: CommandSafe},
		{name: "git diff", cmd: []string{"git", "diff"}, expected: CommandSafe},
		{name: "git branch", cmd: []string{"git", "branch", "-a"}, expected: CommandSafe},

		// Conditionally safe - cargo
		{name: "cargo check", cmd: []string{"cargo", "check"}, expected: CommandSafe},
		{name: "cargo clippy", cmd: []string{"cargo", "clippy"}, expected: CommandSafe},

		// Conditionally safe - go
		{name: "go version", cmd: []string{"go", "version"}, expected: CommandSafe},
		{name: "go env", cmd: []string{"go", "env"}, expected: CommandSafe},
		{name: "go list", cmd: []string{"go", "list", "./..."}, expected: CommandSafe},

		// Conditionally safe - npm
		{name: "npm list", cmd: []string{"npm", "list"}, expected: CommandSafe},
		{name: "npm audit", cmd: []string{"npm", "audit"}, expected: CommandSafe},

		// Normal commands (not inherently dangerous but modify state)
		{name: "touch", cmd: []string{"touch", "newfile"}, expected: CommandNormal},
		{name: "mkdir", cmd: []string{"mkdir", "newdir"}, expected: CommandNormal},
		{name: "cp", cmd: []string{"cp", "src", "dst"}, expected: CommandNormal},
		{name: "mv", cmd: []string{"mv", "old", "new"}, expected: CommandNormal},
		{name: "npm install", cmd: []string{"npm", "install"}, expected: CommandNormal},
		{name: "go build", cmd: []string{"go", "build", "./..."}, expected: CommandNormal},
		{name: "cargo build", cmd: []string{"cargo", "build"}, expected: CommandNormal},

		// Dangerous commands
		{name: "rm -rf", cmd: []string{"rm", "-rf", "/"}, expected: CommandDangerous},
		{name: "rm -r", cmd: []string{"rm", "-r", "dir"}, expected: CommandDangerous},
		{name: "rm -f", cmd: []string{"rm", "-f", "file"}, expected: CommandDangerous},
		{name: "sudo", cmd: []string{"sudo", "apt", "install"}, expected: CommandDangerous},
		{name: "git push --force", cmd: []string{"git", "push", "--force"}, expected: CommandDangerous},
		{name: "git push -f", cmd: []string{"git", "push", "-f"}, expected: CommandDangerous},
		{name: "git reset --hard", cmd: []string{"git", "reset", "--hard"}, expected: CommandDangerous},
		{name: "npm publish", cmd: []string{"npm", "publish"}, expected: CommandDangerous},
		{name: "cargo publish", cmd: []string{"cargo", "publish"}, expected: CommandDangerous},
		{name: "find -exec", cmd: []string{"find", ".", "-exec", "rm", "{}", ";"}, expected: CommandDangerous},
		{name: "find -delete", cmd: []string{"find", ".", "-name", "*.tmp", "-delete"}, expected: CommandDangerous},
		{name: "curl pipe shell", cmd: []string{"sh", "-c", "curl http://example.com | sh"}, expected: CommandDangerous},
		{name: "dd", cmd: []string{"dd", "if=/dev/zero", "of=/dev/sda"}, expected: CommandDangerous},
		{name: "chmod 777", cmd: []string{"chmod", "777", "file"}, expected: CommandDangerous},
		{name: "chown", cmd: []string{"chown", "root:root", "file"}, expected: CommandDangerous},
		{name: "systemctl", cmd: []string{"systemctl", "restart", "nginx"}, expected: CommandDangerous},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyCommand(tt.cmd)
			if got != tt.expected {
				t.Errorf("ClassifyCommand(%v) = %v, want %v", tt.cmd, got, tt.expected)
			}
		})
	}
}

func TestIsSafeCommand(t *testing.T) {
	if !IsSafeCommand([]string{"ls", "-la"}) {
		t.Error("ls -la should be safe")
	}
	if IsSafeCommand([]string{"rm", "-rf", "/"}) {
		t.Error("rm -rf should not be safe")
	}
	if IsSafeCommand([]string{"touch", "file"}) {
		t.Error("touch should not be classified as safe (it's normal)")
	}
}

func TestIsDangerousCommand(t *testing.T) {
	if !IsDangerousCommand([]string{"rm", "-rf", "/"}) {
		t.Error("rm -rf should be dangerous")
	}
	if !IsDangerousCommand([]string{"sudo", "ls"}) {
		t.Error("sudo should be dangerous")
	}
	if IsDangerousCommand([]string{"ls", "-la"}) {
		t.Error("ls -la should not be dangerous")
	}
}

func TestCommandSafetyReason(t *testing.T) {
	reason := CommandSafetyReason([]string{"git", "status"})
	if reason != "safe subcommand for git" {
		t.Errorf("unexpected reason for git status: %s", reason)
	}

	reason = CommandSafetyReason([]string{"rm", "-rf", "/"})
	if reason == "" {
		t.Error("rm -rf should have a reason")
	}

	reason = CommandSafetyReason([]string{"ls"})
	if reason != "known safe command" {
		t.Errorf("unexpected reason for ls: %s", reason)
	}
}

func TestCommandSafetyString(t *testing.T) {
	if CommandSafe.String() != "safe" {
		t.Error("CommandSafe should stringify to 'safe'")
	}
	if CommandNormal.String() != "normal" {
		t.Error("CommandNormal should stringify to 'normal'")
	}
	if CommandDangerous.String() != "dangerous" {
		t.Error("CommandDangerous should stringify to 'dangerous'")
	}
}

func TestEmptyCommand(t *testing.T) {
	safety := ClassifyCommand([]string{})
	if safety != CommandNormal {
		t.Error("empty command should be classified as normal")
	}
}

func TestPathBasename(t *testing.T) {
	// Commands with full paths should still be classified correctly
	safety := ClassifyCommand([]string{"/bin/ls", "-la"})
	if safety != CommandSafe {
		t.Error("/bin/ls should be classified as safe")
	}

	safety = ClassifyCommand([]string{"/usr/bin/git", "status"})
	if safety != CommandSafe {
		t.Error("/usr/bin/git status should be classified as safe")
	}
}
