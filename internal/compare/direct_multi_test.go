package compare

import (
	"path"
	"slices"
	"testing"

	"github.com/temporalio/deputy/internal/ecosystem"
	"github.com/temporalio/deputy/internal/repository/workspace"
)

func TestGetNpmDirectDeps(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected map[string]bool
	}{
		{
			name: "basic dependencies",
			input: `{
				"dependencies": {
					"react": "^18.2.0",
					"lodash": "4.17.21"
				}
			}`,
			expected: map[string]bool{
				"react":  true,
				"lodash": true,
			},
		},
		{
			name: "aliased dependencies record the aliased package",
			input: `{
				"dependencies": {
					"my-lodash": "npm:lodash@^4.17.21",
					"my-scoped": "npm:@babel/core@^7.0.0",
					"unversioned": "npm:left-pad"
				}
			}`,
			expected: map[string]bool{
				"my-lodash":   true,
				"lodash":      true,
				"my-scoped":   true,
				"@babel/core": true,
				"unversioned": true,
				"left-pad":    true,
			},
		},
		{
			name: "dev dependencies",
			input: `{
				"devDependencies": {
					"jest": "^29.0.0",
					"typescript": "^5.0.0"
				}
			}`,
			expected: map[string]bool{
				"jest":       true,
				"typescript": true,
			},
		},
		{
			// npm installs an optionalDependencies entry like any other and the
			// lockfile carries it, so the project declared it and depends on it;
			// only a failed install is tolerated.
			name: "optional dependencies",
			input: `{
				"optionalDependencies": {
					"fsevents": "^2.3.2"
				}
			}`,
			expected: map[string]bool{
				"fsevents": true,
			},
		},
		{
			name: "aliased optional dependencies record the aliased package",
			input: `{
				"optionalDependencies": {
					"my-fsevents": "npm:fsevents@^2.3.2"
				}
			}`,
			expected: map[string]bool{
				"my-fsevents": true,
				"fsevents":    true,
			},
		},
		{
			// A peerDependencies entry is a constraint on whoever installs this
			// package, not a dependency this package declares for itself, so it
			// is deliberately absent. See the note on [getNpmDirectDeps].
			name: "peer dependencies are not this package's own",
			input: `{
				"peerDependencies": {
					"react": "^18.2.0"
				}
			}`,
			expected: map[string]bool{},
		},
		{
			name: "scoped packages",
			input: `{
				"dependencies": {
					"@types/node": "^20.0.0",
					"@babel/core": "^7.0.0"
				}
			}`,
			expected: map[string]bool{
				"@types/node": true,
				"@babel/core": true,
			},
		},
		{
			name: "mixed dependencies",
			input: `{
				"dependencies": {
					"express": "^4.18.0"
				},
				"devDependencies": {
					"nodemon": "^3.0.0"
				}
			}`,
			expected: map[string]bool{
				"express": true,
				"nodemon": true,
			},
		},
		{
			name:     "empty package.json",
			input:    `{}`,
			expected: map[string]bool{},
		},
		{
			name:     "invalid JSON",
			input:    `not json`,
			expected: map[string]bool{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getNpmDirectDeps([]byte(tt.input))
			if len(result) != len(tt.expected) {
				t.Errorf("expected %d deps, got %d", len(tt.expected), len(result))
			}
			for k, v := range tt.expected {
				if result[k] != v {
					t.Errorf("expected %s=%v, got %v", k, v, result[k])
				}
			}
		})
	}
}

func TestGetCargoDirectDeps(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected map[string]bool
	}{
		{
			name: "basic dependencies",
			input: `[package]
name = "myapp"
version = "0.1.0"

[dependencies]
tokio = "1.0"
serde = { version = "1.0", features = ["derive"] }
`,
			expected: map[string]bool{
				"tokio": true,
				"serde": true,
			},
		},
		{
			name: "dev dependencies",
			input: `[package]
name = "myapp"

[dev-dependencies]
criterion = "0.5"
proptest = "1.0"
`,
			expected: map[string]bool{
				"criterion": true,
				"proptest":  true,
			},
		},
		{
			name: "build dependencies",
			input: `[package]
name = "myapp"

[build-dependencies]
cc = "1.0"
`,
			expected: map[string]bool{
				"cc": true,
			},
		},
		{
			name: "mixed dependencies",
			input: `[package]
name = "myapp"

[dependencies]
clap = "4.0"

[dev-dependencies]
assert_cmd = "2.0"

[build-dependencies]
built = "0.7"
`,
			expected: map[string]bool{
				"clap":       true,
				"assert_cmd": true,
				"built":      true,
			},
		},
		{
			name: "with comments",
			input: `[dependencies]
# Main http library
reqwest = "0.11"
# JSON parsing
serde_json = "1.0"
`,
			expected: map[string]bool{
				"reqwest":    true,
				"serde_json": true,
			},
		},
		{
			name: "renamed dependency records the crate it names",
			input: `[dependencies]
my-serde = { package = "serde", version = "1.0" }

[dev-dependencies.my-tokio]
package = "tokio"
version = "1.0"
`,
			expected: map[string]bool{
				"my_serde": true,
				"serde":    true,
				"my_tokio": true,
				"tokio":    true,
			},
		},
		{
			// A platform-conditional dependency is declared by this package, so
			// it is direct. A workspace dependency is a version offered for
			// inheritance, and the member that inherits it records it from its
			// own manifest, so counting it here would mark a crate direct that
			// nothing depends on.
			name: "platform dependencies are direct, workspace declarations are not",
			input: `[target.'cfg(windows)'.dependencies]
winapi = "0.3"

[workspace.dependencies]
anyhow = "1.0"
`,
			expected: map[string]bool{
				"winapi": true,
			},
		},
		{
			name: "hyphenated crate folds to the underscore spelling",
			input: `[dependencies]
serde-json = "1.0"
Async-Trait = "0.1"
`,
			expected: map[string]bool{
				"serde_json":  true,
				"async_trait": true,
			},
		},
		{
			name:     "empty Cargo.toml",
			input:    `[package]`,
			expected: map[string]bool{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getCargoDirectDeps([]byte(tt.input))
			if len(result) != len(tt.expected) {
				t.Errorf("expected %d deps, got %d", len(tt.expected), len(result))
			}
			for k, v := range tt.expected {
				if result[k] != v {
					t.Errorf("expected %s=%v, got %v", k, v, result[k])
				}
			}
		})
	}
}

func TestGetPyprojectDirectDeps(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected map[string]bool
	}{
		{
			name: "PEP 621 dependencies",
			input: `[project]
name = "myapp"
dependencies = ["flask>=2.0", "requests"]
`,
			expected: map[string]bool{
				"flask":    true,
				"requests": true,
			},
		},
		{
			name: "Poetry dependencies",
			input: `[tool.poetry.dependencies]
python = "^3.9"
django = "^4.0"
celery = "^5.0"
`,
			expected: map[string]bool{
				"django": true,
				"celery": true,
			},
		},
		{
			name: "dependency name normalization",
			input: `[tool.poetry.dependencies]
python = "^3.9"
Flask-SQLAlchemy = "^3.0"
google-cloud-storage = "^2.0"
`,
			expected: map[string]bool{
				"flask-sqlalchemy":     true,
				"google-cloud-storage": true,
			},
		},
		{
			name: "PEP 621 with version specifiers",
			input: `[project]
dependencies = ["numpy>=1.20,<2.0", "pandas~=1.5.0", "scipy==1.10.1"]
`,
			expected: map[string]bool{
				"numpy":  true,
				"pandas": true,
				"scipy":  true,
			},
		},
		{
			name: "PEP 621 with extras",
			input: `[project]
dependencies = ["requests[security]>=2.0", "boto3[crt]"]
`,
			expected: map[string]bool{
				"requests": true,
				"boto3":    true,
			},
		},
		{
			name: "Poetry dotted distribution",
			input: `[tool.poetry.dependencies]
zope.interface = "^5.4"
"backports.zoneinfo" = "^0.2"
`,
			expected: map[string]bool{
				"zope-interface":     true,
				"backports-zoneinfo": true,
			},
		},
		{
			name: "PEP 621 direct reference",
			input: `[project]
dependencies = ["my-pkg @ git+https://example.com/my-pkg.git", "requests"]
`,
			expected: map[string]bool{
				"my-pkg":   true,
				"requests": true,
			},
		},
		{
			name:     "empty pyproject.toml",
			input:    `[project]`,
			expected: map[string]bool{},
		},
		{
			name: "PEP 621 multi-line dependencies",
			input: `[project]
name = "my-app"
version = "1.0.0"
dependencies = [
    "celery>=5.3.0",
    "redis>=4.5.0",
]
`,
			expected: map[string]bool{
				"celery": true,
				"redis":  true,
			},
		},
		{
			name: "PEP 621 multi-line with comments",
			input: `[project]
name = "my-app"
dependencies = [
    # Web framework
    "flask>=2.0",
    "requests",
    # Database
    "sqlalchemy>=2.0",
]
`,
			expected: map[string]bool{
				"flask":      true,
				"requests":   true,
				"sqlalchemy": true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getPyprojectDirectDeps([]byte(tt.input))
			if len(result) != len(tt.expected) {
				t.Errorf("expected %d deps, got %d", len(tt.expected), len(result))
				t.Logf("result: %v", result)
			}
			for k, v := range tt.expected {
				if result[k] != v {
					t.Errorf("expected %s=%v, got %v", k, v, result[k])
				}
			}
		})
	}
}

func TestGetRequirementsDirectDeps(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected map[string]bool
	}{
		{
			name: "basic requirements",
			input: `flask==2.0.0
requests>=2.28.0
numpy
`,
			expected: map[string]bool{
				"flask":    true,
				"requests": true,
				"numpy":    true,
			},
		},
		{
			name: "with comments",
			input: `# Web framework
django>=4.0
# Testing
pytest
`,
			expected: map[string]bool{
				"django": true,
				"pytest": true,
			},
		},
		{
			name: "name normalization",
			input: `Flask-RESTful>=0.3.0
google-cloud-bigquery
`,
			expected: map[string]bool{
				"flask-restful":         true,
				"google-cloud-bigquery": true,
			},
		},
		{
			name: "with extras",
			input: `celery[redis]>=5.0
boto3[crt]
`,
			expected: map[string]bool{
				"celery": true,
				"boto3":  true,
			},
		},
		{
			name: "skip options",
			input: `-r other-requirements.txt
-e git+https://github.com/user/repo.git
--index-url https://pypi.org/simple
flask
`,
			expected: map[string]bool{
				"flask": true,
			},
		},
		{
			name: "URL dependencies with @",
			input: `package @ https://example.com/package.tar.gz
normal-package==1.0.0
`,
			expected: map[string]bool{
				"package":        true,
				"normal-package": true,
			},
		},
		{
			name:     "empty requirements.txt",
			input:    ``,
			expected: map[string]bool{},
		},
		{
			name: "only comments",
			input: `# This file is empty
# Nothing here
`,
			expected: map[string]bool{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getRequirementsDirectDeps([]byte(tt.input))
			if len(result) != len(tt.expected) {
				t.Errorf("expected %d deps, got %d", len(tt.expected), len(result))
				t.Logf("result: %v", result)
			}
			for k, v := range tt.expected {
				if result[k] != v {
					t.Errorf("expected %s=%v, got %v", k, v, result[k])
				}
			}
		})
	}
}

func TestMergeDirectDependencies(t *testing.T) {
	t.Run("merge into empty", func(t *testing.T) {
		dst := make(map[string]bool)
		src := map[string]bool{"a": true, "b": true}
		mergeDirectDependencies(dst, src)
		if len(dst) != 2 {
			t.Errorf("expected 2 deps, got %d", len(dst))
		}
	})

	t.Run("merge with existing", func(t *testing.T) {
		dst := map[string]bool{"a": true}
		src := map[string]bool{"b": true, "c": true}
		mergeDirectDependencies(dst, src)
		if len(dst) != 3 {
			t.Errorf("expected 3 deps, got %d", len(dst))
		}
	})

	t.Run("merge with overlap", func(t *testing.T) {
		dst := map[string]bool{"a": true, "b": true}
		src := map[string]bool{"b": true, "c": true}
		mergeDirectDependencies(dst, src)
		if len(dst) != 3 {
			t.Errorf("expected 3 deps, got %d", len(dst))
		}
	})
}

// TestCargoWorkspaceInheritanceDecidesDirect pins what a Cargo workspace makes
// direct. A [workspace.dependencies] entry is a version offered for
// inheritance, and Cargo requires a member to reference it with
// "workspace = true" before anything depends on it. Counting the whole table
// marked a crate direct because its version was declared centrally, so a
// package the lockfile carries only as somebody else's transitive dependency
// showed up as direct in the SBOM and in pkg.direct.
//
// The rename is the part a member's own manifest cannot spell: it writes the
// alias, and only the workspace manifest knows which crate that alias means.
func TestCargoWorkspaceInheritanceDecidesDirect(t *testing.T) {
	tests := []struct {
		name      string
		manifests map[string]string
		want      map[string]bool
		notDirect []string
	}{
		{
			name: "an inherited dependency is direct, an unused declaration is not",
			manifests: map[string]string{
				"Cargo.toml": `[workspace]
members = ["member"]

[workspace.dependencies]
serde = "1.0"
tokio = "1.0"
`,
				"member/Cargo.toml": `[package]
name = "member"

[dependencies]
serde = { workspace = true }
`,
			},
			want:      map[string]bool{"serde": true},
			notDirect: []string{"tokio"},
		},
		{
			name: "an inherited rename records the crate the workspace names",
			manifests: map[string]string{
				"Cargo.toml": `[workspace]
members = ["member"]

[workspace.dependencies]
my-serde = { package = "serde-json", version = "1.0" }
spare-alias = { package = "anyhow", version = "1.0" }
`,
				"member/Cargo.toml": `[package]
name = "member"

[dependencies]
my-serde = { workspace = true }
`,
			},
			want:      map[string]bool{"my_serde": true, "serde_json": true},
			notDirect: []string{"spare_alias", "anyhow"},
		},
		{
			// The alias and the member's own dependency share a name, which is
			// all a check on the collected key set can see. Only the member's
			// entry says whether it inherited, and this one says it did not.
			name: "a member's own dependency sharing an alias name inherits nothing",
			manifests: map[string]string{
				"Cargo.toml": `[workspace]
members = ["member"]

[workspace.dependencies]
my-serde = { package = "serde", version = "1.0" }
`,
				"member/Cargo.toml": `[package]
name = "member"

[dependencies]
my-serde = { path = "../my-serde" }
`,
			},
			want:      map[string]bool{"my_serde": true},
			notDirect: []string{"serde"},
		},
		{
			name: "an alias inherited with the bare workspace key still resolves",
			manifests: map[string]string{
				"Cargo.toml": `[workspace]
members = ["member"]

[workspace.dependencies]
my-serde = { package = "serde", version = "1.0" }
`,
				"member/Cargo.toml": `[package]
name = "member"

[dependencies]
my-serde.workspace = true
`,
			},
			want: map[string]bool{"my_serde": true, "serde": true},
		},
		{
			name: "an alias inherited in a target table still resolves",
			manifests: map[string]string{
				"Cargo.toml": `[workspace]
members = ["member"]

[workspace.dependencies]
my-winapi = { package = "winapi", version = "0.3" }
`,
				"member/Cargo.toml": `[package]
name = "member"

[target.'cfg(windows)'.dependencies]
my-winapi = { workspace = true }
`,
			},
			want: map[string]bool{"my_winapi": true, "winapi": true},
		},
		{
			name: "a member declaring its own dependency needs no workspace table",
			manifests: map[string]string{
				"Cargo.toml": `[workspace]
members = ["member"]
`,
				"member/Cargo.toml": `[package]
name = "member"

[dev-dependencies]
criterion = "0.5"
`,
			},
			want:      map[string]bool{"criterion": true},
			notDirect: []string{"serde"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ws, err := workspace.NewTempDir("cmp-cargo-ws")
			if err != nil {
				t.Fatalf("workspace: %v", err)
			}
			defer ws.Close()
			for name, contents := range tt.manifests {
				if dir := path.Dir(name); dir != "." {
					if err := ws.MkdirAll(dir, 0o755); err != nil {
						t.Fatalf("mkdir %s: %v", dir, err)
					}
				}
				if err := ws.WriteFile(name, []byte(contents), 0o644); err != nil {
					t.Fatalf("write %s: %v", name, err)
				}
			}

			direct := CollectDirectDependenciesFromWorkspace(ws)
			for crate, want := range tt.want {
				if direct[crate] != want {
					t.Errorf("direct[%q] = %v, want %v (collected %v)", crate, direct[crate], want, direct)
				}
			}
			for _, crate := range tt.notDirect {
				if direct[crate] {
					t.Errorf("direct[%q] = true, want it absent (collected %v)", crate, direct)
				}
			}
		})
	}
}

// TestCargoAliasesScopeToTheirWorkspaceRoot pins a rename to the workspace that
// declared it. One repository can hold several independent Cargo workspaces, and
// an alias means whatever the member's own root says it means: two roots are
// free to spell the same alias differently, or to spell one as a rename and the
// other as an ordinary crate of that name. Resolving renames repository-wide
// conflated those, so a member inheriting from its own root got a crate no
// manifest of its workspace ever named, and the rename its root did declare was
// lost to whichever root the walk reached last.
func TestCargoAliasesScopeToTheirWorkspaceRoot(t *testing.T) {
	tests := []struct {
		name      string
		manifests map[string]string
		want      map[string]bool
		notDirect []string
	}{
		{
			// Both roots offer "fast", and each names a different crate. The
			// member that inherits it gets the crate its own root names.
			name: "sibling roots spelling one alias differently keep their own crate",
			manifests: map[string]string{
				"crates/Cargo.toml": `[workspace]
members = ["member"]

[workspace.dependencies]
fast = { package = "serde", version = "1.0" }
`,
				"crates/member/Cargo.toml": `[package]
name = "crates-member"

[dependencies]
fast = { workspace = true }
`,
				"tools/Cargo.toml": `[workspace]
members = ["member"]

[workspace.dependencies]
fast = { package = "rand", version = "0.8" }
`,
				"tools/member/Cargo.toml": `[package]
name = "tools-member"

[dependencies]
fast = { workspace = true }
`,
			},
			want: map[string]bool{"fast": true, "serde": true, "rand": true},
		},
		{
			// Only one root renames "fast"; nobody in that workspace inherits
			// it. The other root offers a crate that is really called fast, and
			// its member takes that. Nothing here depends on serde.
			name: "a rename is not lent to a member of another root",
			manifests: map[string]string{
				"crates/Cargo.toml": `[workspace]
members = ["member"]

[workspace.dependencies]
fast = { package = "serde", version = "1.0" }
`,
				"crates/member/Cargo.toml": `[package]
name = "crates-member"

[dependencies]
anyhow = "1.0"
`,
				"tools/Cargo.toml": `[workspace]
members = ["member"]

[workspace.dependencies]
fast = "0.1"
`,
				"tools/member/Cargo.toml": `[package]
name = "tools-member"

[dependencies]
fast = { workspace = true }
`,
			},
			want:      map[string]bool{"anyhow": true, "fast": true},
			notDirect: []string{"serde"},
		},
		{
			// The nearest root is the one that answers. An inner workspace that
			// declares the name without renaming it must stop the lookup, not
			// hand it on to an outer root that renames it.
			name: "a nested root without the rename does not reach the outer root's",
			manifests: map[string]string{
				"Cargo.toml": `[workspace]
members = ["app"]

[workspace.dependencies]
shared = { package = "serde", version = "1.0" }
`,
				"app/Cargo.toml": `[package]
name = "app"

[dependencies]
anyhow = "1.0"
`,
				"nested/Cargo.toml": `[workspace]
members = ["member"]

[workspace.dependencies]
shared = "0.4"
`,
				"nested/member/Cargo.toml": `[package]
name = "nested-member"

[dependencies]
shared = { workspace = true }
`,
			},
			want:      map[string]bool{"anyhow": true, "shared": true},
			notDirect: []string{"serde"},
		},
		{
			// A root that is not the repository root still governs its members,
			// so scoping must not amount to resolving nothing.
			name: "a rename declared by a nested root resolves for that root's member",
			manifests: map[string]string{
				"crates/Cargo.toml": `[workspace]
members = ["member"]

[workspace.dependencies]
my-serde = { package = "serde", version = "1.0" }
`,
				"crates/member/Cargo.toml": `[package]
name = "crates-member"

[dependencies]
my-serde = { workspace = true }
`,
			},
			want: map[string]bool{"my_serde": true, "serde": true},
		},
		{
			// A root manifest is allowed to be a package too, and it inherits
			// from itself, so the governing root has to be found at the
			// member's own directory as well as above it.
			name: "a root inheriting its own rename resolves against itself",
			manifests: map[string]string{
				"Cargo.toml": `[workspace]
members = ["member"]

[workspace.dependencies]
my-serde = { package = "serde", version = "1.0" }

[package]
name = "root-package"

[dependencies]
my-serde = { workspace = true }
`,
			},
			want: map[string]bool{"my_serde": true, "serde": true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ws, err := workspace.NewTempDir("cmp-cargo-roots")
			if err != nil {
				t.Fatalf("workspace: %v", err)
			}
			defer ws.Close()
			for name, contents := range tt.manifests {
				if dir := path.Dir(name); dir != "." {
					if err := ws.MkdirAll(dir, 0o755); err != nil {
						t.Fatalf("mkdir %s: %v", dir, err)
					}
				}
				if err := ws.WriteFile(name, []byte(contents), 0o644); err != nil {
					t.Fatalf("write %s: %v", name, err)
				}
			}

			direct := CollectDirectDependenciesFromWorkspace(ws)
			for crate, want := range tt.want {
				if direct[crate] != want {
					t.Errorf("direct[%q] = %v, want %v (collected %v)", crate, direct[crate], want, direct)
				}
			}
			for _, crate := range tt.notDirect {
				if direct[crate] {
					t.Errorf("direct[%q] = true, want it absent (collected %v)", crate, direct)
				}
			}
		})
	}
}

// TestDirectDependencyCollectionIsDerivedFromTheParsers pins both halves of the
// coverage answer to the parser table instead of to a list of ecosystem names
// kept beside it. An ecosystem is reported collected exactly when a parser reads
// one of the files the registry declares for it, so writing a parser is what
// widens the answer, and registering an ecosystem nobody parses cannot quietly
// leave a caller thinking its packages were classified.
func TestDirectDependencyCollectionIsDerivedFromTheParsers(t *testing.T) {
	collected := EcosystemsWithDirectDependencyCollection()

	for _, reg := range ecosystem.Default().All() {
		parsed := false
		for _, pattern := range slices.Concat(reg.Manifests, reg.Lockfiles) {
			if _, ok := manifestDirectDepParsers[pattern]; ok || pattern == goDirectDepManifest {
				parsed = true
				break
			}
		}
		reported := slices.Contains(collected, reg.Ecosystem)
		switch {
		case parsed && !reported:
			t.Errorf("%s has a direct dependency parser but is missing from the collection set %v", reg.Ecosystem, collected)
		case !parsed && reported:
			t.Errorf("%s is reported collected but no parser reads %v or %v", reg.Ecosystem, reg.Manifests, reg.Lockfiles)
		}
	}

	// Ecosystems Deputy inventories and cannot classify: the answer callers need
	// in order to tell "transitive" from "not determined here".
	for _, eco := range []ecosystem.Ecosystem{ecosystem.Maven, ecosystem.RubyGems, ecosystem.NuGet, ecosystem.Packagist, ecosystem.CocoaPods, ecosystem.Hex, ecosystem.Pub} {
		if slices.Contains(collected, eco) {
			t.Errorf("%s is reported collected, but nothing here parses its manifests", eco)
		}
	}
}
