package remediation

import (
	"testing"
)

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

// TestValidateExecutable pins the allowlist contract: a manager's own
// executable passes, anything else (wrong executable, unknown manager,
// missing inputs) is rejected before execution.
func TestValidateExecutable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		manager string
		args    []string
		wantErr bool
	}{
		{name: "go allowed", manager: "go", args: []string{"go", "get", "example.com/mod@v1.2.3"}},
		{name: "npm allowed", manager: "npm", args: []string{"npm", "install", "lodash@4.17.21"}},
		// mise fixes are deputy-internal manifest edits, never mise
		// invocations, so the manager stays off the executable allowlist.
		{name: "mise not allowlisted", manager: "mise", args: []string{"mise", "use", "go@1.24.5"}, wantErr: true},
		{name: "manager case and path insensitive", manager: " GO ", args: []string{"/usr/local/bin/go", "get", "example.com/mod@v1.2.3"}},
		{name: "wrong executable for manager", manager: "go", args: []string{"npm", "install"}, wantErr: true},
		{name: "shell rejected", manager: "npm", args: []string{"sh", "-c", "rm -rf /"}, wantErr: true},
		{name: "unknown manager", manager: "not-a-manager", args: []string{"not-a-manager", "install"}, wantErr: true},
		{name: "empty manager", manager: "", args: []string{"go", "get"}, wantErr: true},
		{name: "missing args", manager: "go", args: nil, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateExecutable(tt.manager, tt.args)
			if tt.wantErr && err == nil {
				t.Fatalf("ValidateExecutable(%q, %v) = nil, want error", tt.manager, tt.args)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("ValidateExecutable(%q, %v) = %v, want nil", tt.manager, tt.args, err)
			}
		})
	}
}

// TestRecommendCommand_MiseInternal pins the shape of generated mise fixes:
// a deputy-internal manifest edit targeting the exact detected config file
// (any layout), never a mise invocation. Shelling out to `mise use` fails on
// untrusted configs, picks its own write target, and collapses multi-version
// arrays, so ExecArgs must route these commands to ApplyDeputyCommand instead
// of executing them.
func TestRecommendCommand_MiseInternal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		manifestPath string
		wantCommand  string
	}{
		{
			name:         "default manifest",
			manifestPath: "mise.toml",
			wantCommand:  "deputy:mise:update mise.toml go 1.24.5 1.22.0",
		},
		{
			name:         "hidden manifest",
			manifestPath: ".mise.toml",
			wantCommand:  "deputy:mise:update .mise.toml go 1.24.5 1.22.0",
		},
		{
			name:         "environment-specific manifest",
			manifestPath: "mise.production.toml",
			wantCommand:  "deputy:mise:update mise.production.toml go 1.24.5 1.22.0",
		},
		{
			name:         "config directory manifest",
			manifestPath: ".config/mise/config.toml",
			wantCommand:  "deputy:mise:update .config/mise/config.toml go 1.24.5 1.22.0",
		},
		{
			name:         "conf.d drop-in",
			manifestPath: ".config/mise/conf.d/tools.toml",
			wantCommand:  "deputy:mise:update .config/mise/conf.d/tools.toml go 1.24.5 1.22.0",
		},
		{
			// Paths with whitespace must survive the display-string round-trip
			// (the proto contract omits Args, so apply reparses the command).
			name:         "manifest path with spaces",
			manifestPath: "tool config/mise.toml",
			wantCommand:  `deputy:mise:update "tool config/mise.toml" go 1.24.5 1.22.0`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rec := recommendCommand("mise", tt.manifestPath, "stdlib", []string{"1.22.0"}, "1.24.5", nil, "go")
			if !rec.executable {
				t.Fatalf("expected mise recommendation to be executable, got %#v", rec)
			}
			if rec.command != tt.wantCommand {
				t.Fatalf("recommendCommand = %q, want %q", rec.command, tt.wantCommand)
			}
			if !IsDeputyInternalCommand(rec.command) {
				t.Fatalf("expected a deputy-internal command, got %q", rec.command)
			}
			if len(rec.args) != 0 || rec.followUp != "" || len(rec.followUpArgs) != 0 {
				t.Fatalf("internal command must not carry argv or follow-ups: %#v", rec)
			}

			// The command must round-trip through parsing to the same tokens.
			parts, err := ParseCommandArgs(rec.command)
			if err != nil {
				t.Fatalf("ParseCommandArgs(%q): %v", rec.command, err)
			}
			if parts[1] != tt.manifestPath {
				t.Fatalf("parsed manifest path = %q, want %q", parts[1], tt.manifestPath)
			}

			// ExecArgs must refuse to execute it as a shell command; the apply
			// paths dispatch it to ApplyDeputyCommand instead.
			cmd := Command{
				Manager:    "mise",
				Command:    rec.command,
				Executable: rec.executable,
			}
			if _, err := ExecArgs(cmd); err == nil {
				t.Fatal("ExecArgs should reject deputy-internal commands")
			}
		})
	}
}

// TestRecommendCommand_MiseWithoutManifestPath pins the fallback: with no
// detected manifest there is no file for deputy to edit, so the
// recommendation degrades to non-executable manual guidance instead of a fix
// deputy cannot apply.
func TestRecommendCommand_MiseWithoutManifestPath(t *testing.T) {
	t.Parallel()

	rec := recommendCommand("mise", "", "stdlib", []string{"1.22.0"}, "1.24.5", nil, "go")
	if rec.executable {
		t.Fatalf("expected non-executable guidance, got %#v", rec)
	}
	if rec.command == "" || rec.hint == "" {
		t.Fatalf("expected manual guidance with hint, got %#v", rec)
	}
}

// TestManagerExecutablesCoverGeneratedCommands is a coherence check between
// the command generator and the execution allowlist: every manager for which
// recommendCommand emits an executable command (or executable follow-up) must
// have a managerExecutables entry that accepts it. Deputy-internal commands
// are exempt because ExecArgs routes them to a separate applier.
func TestManagerExecutablesCoverGeneratedCommands(t *testing.T) {
	t.Parallel()

	// One sample per generator branch; manifest paths are chosen to hit the
	// executable variants where the branch is manifest-sensitive.
	tests := []struct {
		manager      string
		manifestPath string
	}{
		{"go", "go.mod"},
		{"npm", "package-lock.json"},
		{"yarn", "yarn.lock"},
		{"pnpm", "pnpm-lock.yaml"},
		{"pip", "requirements.txt"},
		{"pipenv", "Pipfile.lock"},
		{"poetry", "poetry.lock"},
		{"uv", "uv.lock"},
		{"pdm", "pdm.lock"},
		{"conda", "environment.yml"},
		{"mise", "mise.toml"},
		{"asdf", ".tool-versions"},
		{"gem", "Gemfile.lock"},
		{"bundler", "Gemfile.lock"},
		{"composer", "composer.lock"},
		{"cargo", "Cargo.lock"},
		{"maven", "pom.xml"},
		{"gradle", "gradle.lockfile"},
		{"nuget", "packages.lock.json"},
		{"dotnet", "app.csproj"},
		{"hex", "mix.lock"},
		{"mix", "mix.lock"},
		{"pub", "pubspec.lock"},
		{"dart", "pubspec.lock"},
		{"flutter", "pubspec.lock"},
		{"cocoapods", "Podfile.lock"},
		{"pod", "Podfile.lock"},
		{"renv", "renv.lock"},
		{"conan", "conanfile.txt"},
		{"swift", "Package.swift"},
		{"cabal", "example.cabal"},
		{"stack", "stack.yaml"},
	}

	for _, tt := range tests {
		t.Run(tt.manager, func(t *testing.T) {
			t.Parallel()
			rec := recommendCommand(tt.manager, tt.manifestPath, "example", []string{"1.0.0"}, "1.2.3", nil, "")
			if !rec.executable || IsDeputyInternalCommand(rec.command) {
				return
			}
			if len(rec.args) == 0 {
				t.Fatalf("manager %q: executable recommendation has no args: %#v", tt.manager, rec)
			}
			if err := ValidateExecutable(tt.manager, rec.args); err != nil {
				t.Errorf("manager %q: generated command %v rejected by allowlist: %v", tt.manager, rec.args, err)
			}
			if len(rec.followUpArgs) > 0 {
				if err := ValidateExecutable(tt.manager, rec.followUpArgs); err != nil {
					t.Errorf("manager %q: generated follow-up %v rejected by allowlist: %v", tt.manager, rec.followUpArgs, err)
				}
			}
		})
	}
}
