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
			// A distribution whose name contains a dot has to be quoted, because
			// TOML reads a bare dotted key as a nested table. Both entries here
			// are the spelling Poetry accepts.
			name: "Poetry dotted distribution",
			input: `[tool.poetry.dependencies]
"zope.interface" = "^5.4"
"backports.zoneinfo" = "^0.2"
`,
			expected: map[string]bool{
				"zope-interface":     true,
				"backports-zoneinfo": true,
			},
		},
		{
			// The unquoted form is a different declaration, not the same one
			// spelled loosely: TOML makes it the table zope = {interface = "^5.4"},
			// which is not a constraint Poetry can read, so the file is broken and
			// the name it appears to declare is not one this manifest names. Pinned
			// because the line scanner this replaced reported "zope-interface" here,
			// which no TOML reader agrees with.
			name: "Poetry unquoted dotted key is a nested table",
			input: `[tool.poetry.dependencies]
zope.interface = "^5.4"
`,
			expected: map[string]bool{
				"zope": true,
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
		{
			name: "PEP 621 optional-dependencies extras are declarations",
			input: `[project]
name = "my-app"
dependencies = ["flask>=2.0"]

[project.optional-dependencies]
test = ["pytest>=8.0", "coverage"]
docs = ["sphinx>=7.0"]
`,
			expected: map[string]bool{
				"flask":    true,
				"pytest":   true,
				"coverage": true,
				"sphinx":   true,
			},
		},
		{
			name: "Poetry group dependencies are declarations",
			input: `[tool.poetry.dependencies]
python = "^3.9"
django = "^4.0"

[tool.poetry.group.dev.dependencies]
pytest = "^8.0"
ruff = "^0.5"

[tool.poetry.group.docs.dependencies]
sphinx = "^7.0"
`,
			expected: map[string]bool{
				"django": true,
				"pytest": true,
				"ruff":   true,
				"sphinx": true,
			},
		},
		{
			name: "Poetry legacy dev-dependencies are declarations",
			input: `[tool.poetry.dependencies]
python = "^3.9"
django = "^4.0"

[tool.poetry.dev-dependencies]
pytest = "^8.0"
`,
			expected: map[string]bool{
				"django": true,
				"pytest": true,
			},
		},
		{
			name: "PEP 735 dependency-groups are declarations",
			input: `[project]
dependencies = ["flask>=2.0"]

[dependency-groups]
test = ["pytest>=8.0", "coverage"]
lint = ["ruff", {include-group = "test"}]
`,
			expected: map[string]bool{
				"flask":    true,
				"pytest":   true,
				"coverage": true,
				"ruff":     true,
			},
		},
		{
			name: "an extra declared only under an extras table still counts",
			input: `[project]
name = "my-app"

[project.optional-dependencies]
aws = ["boto3[crt]>=1.34", "Flask-SQLAlchemy"]
`,
			expected: map[string]bool{
				"boto3":            true,
				"flask-sqlalchemy": true,
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
	collected := ecosystemsWithDirectDependencyCollection()

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

// npmDuplicateVersionLock is the shape npm writes when the project declares one
// version of a package and a dependency of the project pins an incompatible
// one: the project's copy takes the top-level slot and the other is nested.
// Duplicate versions of one name are ordinary in npm, and the lockfile is the
// only file that says which version the declaration resolved to.
const npmDuplicateVersionLock = `{
  "name": "app",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "app", "dependencies": {"lodash": "^4.17.21", "legacy-thing": "^1.0.0"}, "devDependencies": {"jest": "^29.0.0"}},
    "node_modules/lodash": {"version": "4.17.21"},
    "node_modules/jest": {"version": "29.7.0"},
    "node_modules/legacy-thing": {"version": "1.0.0", "dependencies": {"lodash": "3.10.1"}},
    "node_modules/legacy-thing/node_modules/lodash": {"version": "3.10.1"}
  }
}`

// TestGetNpmLockDirectDeps pins what the lockfile adds over the manifest: the
// resolved version of every name the project declares, plus the marker that says
// a name's versions were resolved at all. Both directions matter, so the nested
// copy's absence from the map is asserted as explicitly as the declared copy's
// presence.
func TestGetNpmLockDirectDeps(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  map[string]bool
	}{
		{
			name:  "one key per resolved declaration, and nothing else",
			input: npmDuplicateVersionLock,
			want: map[string]bool{
				"lodash@4.17.21":     true,
				"jest@29.7.0":        true,
				"legacy-thing@1.0.0": true,
			},
		},
		{
			name: "an alias resolves under the name the lockfile reports",
			input: `{
  "lockfileVersion": 3,
  "packages": {
    "": {"dependencies": {"my-lodash": "npm:lodash@^4.17.21"}},
    "node_modules/my-lodash": {"name": "lodash", "version": "4.17.21"}
  }
}`,
			want: map[string]bool{"lodash@4.17.21": true},
		},
		{
			name: "a scoped package keeps its scope",
			input: `{
  "lockfileVersion": 3,
  "packages": {
    "": {"devDependencies": {"@types/node": "^20.0.0"}},
    "node_modules/@types/node": {"version": "20.11.5"}
  }
}`,
			want: map[string]bool{"@types/node@20.11.5": true},
		},
		{
			name: "a declaration with no resolvable version gets no marker",
			input: `{
  "lockfileVersion": 3,
  "packages": {
    "": {"dependencies": {"local-thing": "file:../local-thing", "lodash": "^4.0.0"}},
    "node_modules/local-thing": {"resolved": "../local-thing", "link": true},
    "node_modules/lodash": {"version": "4.17.21"}
  }
}`,
			want: map[string]bool{"lodash@4.17.21": true},
		},
		{
			name: "a v1 lockfile cannot distinguish top-level from hoisted",
			input: `{
  "lockfileVersion": 1,
  "dependencies": {"lodash": {"version": "4.17.21"}}
}`,
			want: map[string]bool{},
		},
		{
			name:  "a lockfile that does not parse yields nothing",
			input: `{not json`,
			want:  map[string]bool{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getNpmLockDirectDeps([]byte(tt.input))
			if len(got) != len(tt.want) {
				t.Errorf("got %d keys, want %d\n got:  %v\n want: %v", len(got), len(tt.want), got, tt.want)
			}
			for k, v := range tt.want {
				if got[k] != v {
					t.Errorf("key %q = %v, want %v (got map %v)", k, got[k], v, got)
				}
			}
			// The nested copy must never earn a key of its own.
			if got["lodash@3.10.1"] {
				t.Errorf("nested transitive copy was recorded as a resolved declaration: %v", got)
			}
		})
	}
}

// TestLookupDirectPrefersResolvedVersion pins the rule both sides of the
// directness lookup share: once a name's versions are resolved, only those
// versions are direct, and a name with no resolution keeps the name-only answer
// so a project without a committed lockfile classifies exactly as before.
func TestLookupDirectPrefersResolvedVersion(t *testing.T) {
	resolved := map[string]bool{
		"lodash@4.17.21": true,
		"tokio":          true,
	}

	tests := []struct {
		name    string
		pkgName string
		version string
		want    bool
	}{
		{name: "the resolved version is direct", pkgName: "lodash", version: "4.17.21", want: true},
		{name: "a nested copy of a declared name is not", pkgName: "lodash", version: "3.10.1", want: false},
		{name: "a name with no resolution falls back to the name", pkgName: "tokio", version: "1.26.0", want: true},
		{name: "a name nothing declares is not direct", pkgName: "left-pad", version: "1.3.0", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := LookupDirect(resolved, tt.pkgName, tt.version); got != tt.want {
				t.Errorf("LookupDirect(%q, %q) = %v, want %v", tt.pkgName, tt.version, got, tt.want)
			}
		})
	}
}

// TestDirectSetIsPerProjectAcrossOneRepository pins the property a scan-wide
// lookup table has to have: one project's resolution must not answer for another
// project's declaration.
//
// A repository can hold an npm-locked project beside one Deputy cannot resolve
// (Yarn, pnpm, or no lockfile at all). The locked project resolves lodash 4, and
// the unlocked one declares lodash ^3. Both declarations are real, and a third
// copy is nobody's declaration, so all three answers differ and every one of them
// has to come out of the same flat map.
func TestDirectSetIsPerProjectAcrossOneRepository(t *testing.T) {
	files := map[string]string{
		"locked/package.json": `{"name":"locked","dependencies":{"lodash":"^4.17.21","legacy-thing":"^1.0.0"}}`,
		"locked/package-lock.json": `{
  "name": "locked",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "locked", "dependencies": {"lodash": "^4.17.21", "legacy-thing": "^1.0.0"}},
    "node_modules/lodash": {"version": "4.17.21"},
    "node_modules/legacy-thing": {"version": "1.0.0", "dependencies": {"lodash": "2.4.2"}},
    "node_modules/legacy-thing/node_modules/lodash": {"version": "2.4.2"}
  }
}`,
		"unlocked/package.json": `{"name":"unlocked","dependencies":{"lodash":"^3.10.1"}}`,
		"unlocked/yarn.lock":    "lodash@^3.10.1:\n  version \"3.10.1\"\n",
	}

	ws := workspace.NewMemory()
	t.Cleanup(func() { _ = ws.Close() })
	for name, contents := range files {
		if err := ws.WriteFile(name, []byte(contents), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	direct := CollectDirectDependenciesFromWorkspace(ws)

	tests := []struct {
		name    string
		version string
		want    bool
	}{
		{name: "the locked project's resolved version is direct", version: "4.17.21", want: true},
		{name: "the unlocked project's declared version is direct", version: "3.10.1", want: true},
		// The deliberate cost of getting the line above right. The unlocked
		// project declares lodash and nothing here can say which version that
		// resolved to, so its name key answers for every copy of the name in the
		// scan, including the locked project's transitive one. Narrowing this
		// would take knowing which project a scanned package belongs to, which
		// the lookup is not given. Over-claiming one transitive copy is the
		// better failure: the alternative denies a declaration a project made.
		{name: "a copy only the locked project has is over-claimed, not denied", version: "2.4.2", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := LookupDirect(direct, "lodash", tt.version); got != tt.want {
				t.Errorf("LookupDirect(lodash, %s) = %v, want %v\ncollected: %v",
					tt.version, got, tt.want, direct)
			}
		})
	}
}

// TestDirectSetIsMonotone pins the invariant that replaced the resolution
// marker. Every entry is a positive statement about some project, so adding
// entries can only make packages direct, never undo it. That is what makes one
// flat map safe for a whole scan: a second project's contribution cannot deny the
// first project's declaration, whatever order the walk visited them in.
//
// The marker broke exactly this. It meant "some project resolved versions for
// this name", which read as though it held everywhere, so adding it took
// directness away from a package another project had declared. Any future key
// that is a statement about a project rather than about a package will fail here.
func TestDirectSetIsMonotone(t *testing.T) {
	// Every key any of the collectors can produce, from two projects that
	// disagree about lodash.
	contributions := []map[string]bool{
		{"lodash@4.17.21": true},
		{"lodash": true},
		{"legacy-thing@1.0.0": true},
		{"stdlib": true, "go": true},
	}
	probes := []struct{ name, version string }{
		{"lodash", "4.17.21"},
		{"lodash", "3.10.1"},
		{"lodash", ""},
		{"legacy-thing", "1.0.0"},
		{"left-pad", "1.3.0"},
	}

	direct := make(map[string]bool)
	was := make(map[string]bool, len(probes))
	for _, p := range probes {
		was[p.name+"\x00"+p.version] = LookupDirect(direct, p.name, p.version)
	}

	for i, contribution := range contributions {
		mergeDirectDependencies(direct, contribution)
		for _, p := range probes {
			key := p.name + "\x00" + p.version
			got := LookupDirect(direct, p.name, p.version)
			if was[key] && !got {
				t.Errorf("after contribution %d, %s@%s went from direct to indirect: an entry took directness away\nset: %v",
					i, p.name, p.version, direct)
			}
			was[key] = got
		}
	}
}

// TestNpmAliasResolutionSuppressesBothSpellings covers the alias case. An entry
// such as my-lodash: "npm:lodash@^4" is installed under the alias and records the
// package it really is, so the lockfile answers for it under the target's name
// and version. The manifest contributes both spellings, and only the target was
// being suppressed, which left the alias answering by name: a package genuinely
// called my-lodash, arriving transitively at any version, then read as direct.
func TestNpmAliasResolutionSuppressesBothSpellings(t *testing.T) {
	files := map[string]string{
		"package.json": `{"name":"app","dependencies":{"my-lodash":"npm:lodash@^4.17.21"}}`,
		"package-lock.json": `{
  "name": "app",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "app", "dependencies": {"my-lodash": "npm:lodash@^4.17.21"}},
    "node_modules/my-lodash": {"name": "lodash", "version": "4.17.21"}
  }
}`,
	}
	ws := workspace.NewMemory()
	t.Cleanup(func() { _ = ws.Close() })
	for name, contents := range files {
		if err := ws.WriteFile(name, []byte(contents), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	direct := CollectDirectDependenciesFromWorkspace(ws)

	if !LookupDirect(direct, "lodash", "4.17.21") {
		t.Errorf("the aliased package is not direct at its resolved version\nset: %v", direct)
	}
	// The alias is a name npm registers nothing under, but nothing stops a real
	// package from having it, and the declaration resolved to something else.
	if LookupDirect(direct, "my-lodash", "9.9.9") {
		t.Errorf("a package named like the alias is direct at a version nothing declared\nset: %v", direct)
	}
	if direct["my-lodash"] {
		t.Errorf("the alias kept a bare key even though the declaration was resolved\nset: %v", direct)
	}
}

// TestNpmShrinkwrapGovernsOverPackageLock pins the collector to the same
// precedence the inventory applies. SCALIBR's packagelockjson extractor ignores
// package-lock.json outright when a sibling npm-shrinkwrap.json exists, so a
// stale package-lock must not contribute resolutions here either: it would answer
// for a version the inventory never reports, while the version inventory does
// report has no key and loses to the suppressed declaration.
func TestNpmShrinkwrapGovernsOverPackageLock(t *testing.T) {
	files := map[string]string{
		"package.json": `{"name":"app","dependencies":{"lodash":"^4.17.0"}}`,
		// Stale, and what npm and the inventory both ignore.
		"package-lock.json": `{
  "name": "app",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "app", "dependencies": {"lodash": "^4.17.0"}},
    "node_modules/lodash": {"version": "4.17.20"}
  }
}`,
		"npm-shrinkwrap.json": `{
  "name": "app",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "app", "dependencies": {"lodash": "^4.17.0"}},
    "node_modules/lodash": {"version": "4.17.21"}
  }
}`,
	}
	ws := workspace.NewMemory()
	t.Cleanup(func() { _ = ws.Close() })
	for name, contents := range files {
		if err := ws.WriteFile(name, []byte(contents), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	direct := CollectDirectDependenciesFromWorkspace(ws)

	if !LookupDirect(direct, "lodash", "4.17.21") {
		t.Errorf("the version the shrinkwrap resolved is not direct\nset: %v", direct)
	}
	if LookupDirect(direct, "lodash", "4.17.20") {
		t.Errorf("the stale package-lock's version is direct, so package-lock was not ignored\nset: %v", direct)
	}
}

// TestNpmShrinkwrapAloneStillResolves keeps the precedence from swallowing the
// ordinary case: a shrinkwrap with no package-lock beside it governs on its own.
func TestNpmShrinkwrapAloneStillResolves(t *testing.T) {
	files := map[string]string{
		"package.json": `{"name":"app","dependencies":{"lodash":"^4.17.0"}}`,
		"npm-shrinkwrap.json": `{
  "name": "app",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "app", "dependencies": {"lodash": "^4.17.0"}},
    "node_modules/lodash": {"version": "4.17.21"},
    "node_modules/legacy": {"version": "1.0.0", "dependencies": {"lodash": "3.10.1"}},
    "node_modules/legacy/node_modules/lodash": {"version": "3.10.1"}
  }
}`,
	}
	ws := workspace.NewMemory()
	t.Cleanup(func() { _ = ws.Close() })
	for name, contents := range files {
		if err := ws.WriteFile(name, []byte(contents), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	direct := CollectDirectDependenciesFromWorkspace(ws)

	if !LookupDirect(direct, "lodash", "4.17.21") {
		t.Errorf("a shrinkwrap on its own did not resolve the declaration\nset: %v", direct)
	}
	if LookupDirect(direct, "lodash", "3.10.1") {
		t.Errorf("the nested copy is direct, so the shrinkwrap did not narrow the name\nset: %v", direct)
	}
}

// TestNestedStandaloneProjectKeepsItsOwnAnswer guards the ancestor walk that
// workspace members need. A member keeps its declarations in its own
// package.json while the lockfile sits at the workspace root, so the search for a
// governing lockfile has to look upward; but a project the root does not claim is
// not a member, and letting the root's lockfile answer for it suppressed a
// declaration the root never resolved.
//
// Here the root is an ordinary npm project, not a workspace at all, and tools/ is
// a separate Yarn project declaring a different major of the same package. Nothing
// resolved the nested declaration, so it keeps the name-only answer rather than
// being denied by a lockfile that never mentioned it.
func TestNestedStandaloneProjectKeepsItsOwnAnswer(t *testing.T) {
	files := map[string]string{
		"package.json": `{"name":"root","dependencies":{"lodash":"^4.17.21"}}`,
		"package-lock.json": `{
  "name": "root",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "root", "dependencies": {"lodash": "^4.17.21"}},
    "node_modules/lodash": {"version": "4.17.21"}
  }
}`,
		"tools/package.json": `{"name":"tools","dependencies":{"lodash":"^3.10.1"}}`,
		"tools/yarn.lock":    "lodash@^3.10.1:\n  version \"3.10.1\"\n",
	}
	ws := workspace.NewMemory()
	t.Cleanup(func() { _ = ws.Close() })
	for name, contents := range files {
		if err := ws.WriteFile(name, []byte(contents), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	direct := CollectDirectDependenciesFromWorkspace(ws)

	if !LookupDirect(direct, "lodash", "4.17.21") {
		t.Errorf("the root's resolved version is not direct\nset: %v", direct)
	}
	if !LookupDirect(direct, "lodash", "3.10.1") {
		t.Errorf("the nested project's declaration was denied by a lockfile that does not claim it\nset: %v", direct)
	}
}

// TestWorkspaceMemberIsStillGovernedByTheRootLock is the other side of the same
// rule, so the fix for the nested project cannot be "stop looking upward". A
// member the root claims through its workspaces globs is resolved by the root's
// lockfile, and its nested copy stays transitive.
func TestWorkspaceMemberIsStillGovernedByTheRootLock(t *testing.T) {
	files := map[string]string{
		"package.json":              `{"name":"monorepo","workspaces":["packages/*"]}`,
		"packages/api/package.json": `{"name":"@acme/api","dependencies":{"lodash":"^4.17.21"}}`,
		"package-lock.json": `{
  "name": "monorepo",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "monorepo", "workspaces": ["packages/*"]},
    "packages/api": {"name": "@acme/api", "dependencies": {"lodash": "^4.17.21"}},
    "node_modules/@acme/api": {"resolved": "packages/api", "link": true},
    "node_modules/lodash": {"version": "4.17.21"},
    "node_modules/legacy": {"version": "1.0.0", "dependencies": {"lodash": "3.10.1"}},
    "node_modules/legacy/node_modules/lodash": {"version": "3.10.1"}
  }
}`,
	}
	ws := workspace.NewMemory()
	t.Cleanup(func() { _ = ws.Close() })
	for name, contents := range files {
		if err := ws.WriteFile(name, []byte(contents), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	direct := CollectDirectDependenciesFromWorkspace(ws)

	if !LookupDirect(direct, "lodash", "4.17.21") {
		t.Errorf("the member's declaration was not resolved by the root lockfile\nset: %v", direct)
	}
	if LookupDirect(direct, "lodash", "3.10.1") {
		t.Errorf("the nested copy is direct, so the member kept a bare key\nset: %v", direct)
	}
}

// TestOneMembersResolutionDoesNotDenyAnothersDeclaration is the two-member case
// that a per-project scoping of the lockfile does not by itself get right. One
// governing lockfile answers for every member of the workspace, so scoping the
// lookup to the lockfile leaves every member reading the same set of resolved
// names.
//
// Here @acme/api declares lodash and the lockfile resolves it to a registry
// version, while @acme/tools declares lodash as a "file:" dependency whose entry
// is a link with no version. The second declaration produced no version key, so
// the bare name is the only answer it can have; consulting the lockfile-wide
// union took that away, because the first member's declaration had marked the
// name resolved. The copy @acme/tools explicitly depends on then reached SBOMs
// and direct-only policies as transitive.
//
// left-pad is the control that keeps the answer from being "stop suppressing".
// @acme/web declares it and the lockfile resolves it, so the nested copy a
// transitive package pins stays transitive.
func TestOneMembersResolutionDoesNotDenyAnothersDeclaration(t *testing.T) {
	files := map[string]string{
		"package.json":                `{"name":"monorepo","workspaces":["packages/*"]}`,
		"packages/api/package.json":   `{"name":"@acme/api","dependencies":{"lodash":"^4.17.21"}}`,
		"packages/tools/package.json": `{"name":"@acme/tools","dependencies":{"lodash":"file:../../local/lodash"}}`,
		"packages/web/package.json":   `{"name":"@acme/web","dependencies":{"left-pad":"^1.3.0"}}`,
		"local/lodash/package.json":   `{"name":"lodash","version":"0.0.0-local"}`,
		"package-lock.json": `{
  "name": "monorepo",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "monorepo", "workspaces": ["packages/*"]},
    "packages/api": {"name": "@acme/api", "dependencies": {"lodash": "^4.17.21"}},
    "packages/tools": {"name": "@acme/tools", "dependencies": {"lodash": "file:../../local/lodash"}},
    "packages/web": {"name": "@acme/web", "dependencies": {"left-pad": "^1.3.0"}},
    "node_modules/@acme/api": {"resolved": "packages/api", "link": true},
    "node_modules/@acme/tools": {"resolved": "packages/tools", "link": true},
    "node_modules/@acme/web": {"resolved": "packages/web", "link": true},
    "node_modules/lodash": {"version": "4.17.21"},
    "node_modules/left-pad": {"version": "1.3.0"},
    "node_modules/legacy": {"version": "1.0.0", "dependencies": {"left-pad": "0.0.9"}},
    "node_modules/legacy/node_modules/left-pad": {"version": "0.0.9"},
    "packages/tools/node_modules/lodash": {"resolved": "local/lodash", "link": true}
  }
}`,
	}
	ws := workspace.NewMemory()
	t.Cleanup(func() { _ = ws.Close() })
	for name, contents := range files {
		if err := ws.WriteFile(name, []byte(contents), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	direct := CollectDirectDependenciesFromWorkspace(ws)

	tests := []struct {
		name    string
		pkg     string
		version string
		want    bool
	}{
		{
			name:    "the member whose declaration the lockfile resolved is direct",
			pkg:     "lodash",
			version: "4.17.21",
			want:    true,
		},
		{
			name:    "the member whose file: declaration got no version is direct too",
			pkg:     "lodash",
			version: "0.0.0-local",
			want:    true,
		},
		{
			name:    "a fully resolved member's declaration is still direct",
			pkg:     "left-pad",
			version: "1.3.0",
			want:    true,
		},
		{
			// The control. Every member that declares left-pad had its
			// declaration resolved, so nothing contributes a bare key for the
			// name and a copy nobody declared stays transitive. Suppression is
			// narrowed to the declaration site, not switched off.
			name:    "a nested copy no member declared stays transitive",
			pkg:     "left-pad",
			version: "0.0.9",
			want:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := LookupDirect(direct, tt.pkg, tt.version); got != tt.want {
				t.Errorf("LookupDirect(%s, %s) = %v, want %v\nset: %v",
					tt.pkg, tt.version, got, tt.want, direct)
			}
		})
	}
}
