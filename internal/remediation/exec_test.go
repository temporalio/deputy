package remediation

import "testing"

func TestParseCommandArgs(t *testing.T) {
	t.Parallel()

	args, err := ParseCommandArgs(`uv add "urllib3>=2.6.3"`)
	if err != nil {
		t.Fatalf("ParseCommandArgs error: %v", err)
	}
	if len(args) != 3 || args[0] != "uv" || args[1] != "add" || args[2] != "urllib3>=2.6.3" {
		t.Fatalf("unexpected args: %#v", args)
	}
}

func TestExecArgs_UsesExplicitArgs(t *testing.T) {
	t.Parallel()

	cmd := Command{
		Manager:    "npm",
		Command:    "npm install lodash@4.17.21",
		Args:       []string{"npm", "install", "lodash@4.17.21"},
		Executable: true,
	}
	args, err := ExecArgs(cmd)
	if err != nil {
		t.Fatalf("ExecArgs error: %v", err)
	}
	if len(args) != 3 || args[0] != "npm" {
		t.Fatalf("unexpected args: %#v", args)
	}
}

func TestExecArgs_RejectsUnknownExecutable(t *testing.T) {
	t.Parallel()

	cmd := Command{
		Manager:    "go",
		Command:    "sh -c rm -rf /",
		Executable: true,
	}
	if _, err := ExecArgs(cmd); err == nil {
		t.Fatal("ExecArgs should reject unknown executable")
	}
}
