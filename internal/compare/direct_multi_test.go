package compare

import (
	"testing"
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
