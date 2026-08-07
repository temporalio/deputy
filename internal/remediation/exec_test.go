package remediation

import (
	"slices"
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
		{name: "mise allowed", manager: "mise", args: []string{"mise", "use", "go@1.24.5"}},
		{name: "mise follow-up allowed", manager: "mise", args: []string{"mise", "install"}},
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

// TestExecArgs_MiseCommand pins the end-to-end path for a generated mise fix:
// the generator marks `mise use` executable, so the allowlist must accept it,
// otherwise deputy recommends a fix it can never apply. It also pins the
// --path targeting: `mise use` chooses its own write target by default (the
// lowest-precedence config in the working directory), so the generated
// command must address the detected manifest explicitly by basename (the
// apply paths run the command in the manifest's directory).
func TestExecArgs_MiseCommand(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		manifestPath string
		wantArgs     []string
	}{
		{
			name:         "default manifest",
			manifestPath: "mise.toml",
			wantArgs:     []string{"mise", "use", "--path", "mise.toml", "go@1.24.5"},
		},
		{
			name:         "hidden manifest",
			manifestPath: ".mise.toml",
			wantArgs:     []string{"mise", "use", "--path", ".mise.toml", "go@1.24.5"},
		},
		{
			name:         "environment-specific manifest",
			manifestPath: "mise.production.toml",
			wantArgs:     []string{"mise", "use", "--path", "mise.production.toml", "go@1.24.5"},
		},
		{
			// The apply paths chdir to .config/mise, so the basename is the
			// correct relative target there.
			name:         "config directory manifest",
			manifestPath: ".config/mise/config.toml",
			wantArgs:     []string{"mise", "use", "--path", "config.toml", "go@1.24.5"},
		},
		{
			name:         "conf.d drop-in",
			manifestPath: ".config/mise/conf.d/tools.toml",
			wantArgs:     []string{"mise", "use", "--path", "tools.toml", "go@1.24.5"},
		},
		{
			// With no manifest path, omit --path and let mise resolve its
			// default write target.
			name:         "no manifest path",
			manifestPath: "",
			wantArgs:     []string{"mise", "use", "go@1.24.5"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rec := recommendCommand("mise", tt.manifestPath, "stdlib", "1.24.5", nil, "go")
			if !rec.executable {
				t.Fatalf("expected mise recommendation to be executable, got %#v", rec)
			}
			if !slices.Equal(rec.args, tt.wantArgs) {
				t.Fatalf("recommendCommand args = %v, want %v", rec.args, tt.wantArgs)
			}

			cmd := Command{
				Manager:    "mise",
				Command:    rec.command,
				Args:       rec.args,
				Executable: rec.executable,
			}
			args, err := ExecArgs(cmd)
			if err != nil {
				t.Fatalf("ExecArgs error: %v", err)
			}
			if !slices.Equal(args, tt.wantArgs) {
				t.Fatalf("ExecArgs = %v, want %v", args, tt.wantArgs)
			}
			if err := ValidateExecutable(cmd.Manager, rec.followUpArgs); err != nil {
				t.Fatalf("follow-up %v not allowed: %v", rec.followUpArgs, err)
			}
		})
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
			rec := recommendCommand(tt.manager, tt.manifestPath, "example", "1.2.3", nil, "")
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
