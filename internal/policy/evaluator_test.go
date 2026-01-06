package policy

import (
	"testing"
)

func TestEvaluateSimplePolicy(t *testing.T) {
	const src = `
(sbom.?component.?licenses[?0].orValue("UNKNOWN") in ["GPL-3.0-only"]
  ? [{"action": "deny", "reason": "bad"}]
  : [{"action": "allow"}])`

	input := map[string]any{
		"sbom": map[string]any{
			"component": map[string]any{
				"licenses": []any{"GPL-3.0-only"},
			},
		},
	}
	val, err := Evaluate(t.Context(), src, input)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	res, ok := val.([]any)
	if !ok {
		t.Fatalf("expected []any result, got %T", val)
	}
	if len(res) != 1 {
		t.Fatalf("expected one action, got %d", len(res))
	}
	action, ok := res[0].(map[string]any)
	if !ok {
		t.Fatalf("expected map action, got %T", res[0])
	}
	if action["action"] != "deny" {
		t.Fatalf("expected deny action, got %v", action["action"])
	}
}

func TestCelExtensions(t *testing.T) {
	t.Run("lists slice and repeat", func(t *testing.T) {
		src := `["a","b","c","d"].slice(1,3).reverse().join(",")`
		val, err := Evaluate(t.Context(), src, nil)
		if err != nil {
			t.Fatalf("Evaluate lists: %v", err)
		}
		if s, ok := val.(string); !ok || s != "c,b" {
			t.Fatalf("unexpected value %v", val)
		}
	})

	t.Run("sets contains dedup", func(t *testing.T) {
		src := `sets.contains(["a","b","c"], ["b","c"]) && sets.equivalent(["a","a","b","c"], ["c","b","a"])`
		val, err := Evaluate(t.Context(), src, nil)
		if err != nil {
			t.Fatalf("Evaluate sets: %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Fatalf("expected true, got %v", val)
		}
	})

	t.Run("regex partial match", func(t *testing.T) {
		src := `regex.extractAll("foo123bar456", "\\d+").size() == 2 && regex.extract("foo123", "foo(\\d+)").orValue("") == "123"`
		val, err := Evaluate(t.Context(), src, nil)
		if err != nil {
			t.Fatalf("Evaluate regex: %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Fatalf("expected true, got %v", val)
		}
	})
}

func TestEvaluatePkgHelper(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]any
		expected string // expected pkg.name
	}{
		{
			name: "component package name",
			input: map[string]any{
				"component": map[string]any{"package": "comp-pkg"},
				"request":   map[string]any{"package": "req-pkg"},
			},
			expected: "comp-pkg",
		},
		{
			name: "request package name fallback",
			input: map[string]any{
				"request": map[string]any{"package": "req-pkg"},
			},
			expected: "req-pkg",
		},
		{
			name: "module name fallback",
			input: map[string]any{
				"component": map[string]any{"module": "mod-name"},
			},
			expected: "mod-name",
		},
		{
			name: "generic name fallback",
			input: map[string]any{
				"component": map[string]any{"name": "gen-name"},
			},
			expected: "gen-name",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// We evaluate a simple expression that returns pkg.name
			src := `pkg.name`
			val, err := Evaluate(t.Context(), src, test.input)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if s, ok := val.(string); !ok || s != test.expected {
				t.Errorf("expected pkg.name = %q, got %v", test.expected, val)
			}
		})
	}
}

func TestPkgHelperDefaults(t *testing.T) {
	// Test that pkg fields have sensible defaults when not provided,
	// allowing policies to use them directly without ?.orValue() boilerplate.
	t.Run("licenses defaults to empty list", func(t *testing.T) {
		input := map[string]any{
			"component": map[string]any{"name": "test-pkg"},
		}
		// This should work without ?.orValue() because licenses defaults to []
		src := `pkg.licenses.size() == 0`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected pkg.licenses to be empty list, got %v", val)
		}
	})

	t.Run("licenses exists works without orValue", func(t *testing.T) {
		input := map[string]any{
			"component": map[string]any{"name": "test-pkg"},
		}
		// This should work without ?.orValue()
		src := `!pkg.licenses.exists(l, l == "GPL-3.0")`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected pkg.licenses.exists to work on empty list")
		}
	})

	t.Run("version defaults to empty string", func(t *testing.T) {
		input := map[string]any{
			"component": map[string]any{"name": "test-pkg"},
		}
		src := `pkg.version == ""`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected pkg.version to default to empty string")
		}
	})

	t.Run("ecosystem defaults to empty string", func(t *testing.T) {
		input := map[string]any{
			"component": map[string]any{"name": "test-pkg"},
		}
		src := `pkg.ecosystem == ""`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected pkg.ecosystem to default to empty string")
		}
	})

	t.Run("actual values override defaults", func(t *testing.T) {
		input := map[string]any{
			"component": map[string]any{
				"name":      "test-pkg",
				"version":   "1.2.3",
				"ecosystem": "npm",
				"licenses":  []any{"MIT", "Apache-2.0"},
			},
		}
		src := `pkg.version == "1.2.3" && pkg.ecosystem == "npm" && pkg.licenses.size() == 2`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected actual values to override defaults")
		}
	})

	t.Run("string methods work on default version", func(t *testing.T) {
		input := map[string]any{
			"component": map[string]any{"name": "test-pkg"},
		}
		// String methods should work on empty string default
		src := `!pkg.version.startsWith("v") && !pkg.version.matches(".*alpha.*")`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected string methods to work on default empty version")
		}
	})

	t.Run("pkg always exists with defaults even without component/request", func(t *testing.T) {
		// When there's no component or request, pkg should still exist with all defaults
		input := map[string]any{
			"env": map[string]any{"command": "scan"},
		}
		src := `pkg.name == "" && pkg.version == "" && pkg.ecosystem == "" && pkg.licenses.size() == 0`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected pkg to exist with all defaults when no component/request present")
		}
	})

	t.Run("name defaults to empty string", func(t *testing.T) {
		// Even with component that has no name, pkg.name should be empty string
		input := map[string]any{
			"component": map[string]any{"licenses": []any{"MIT"}},
		}
		src := `pkg.name == ""`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected pkg.name to default to empty string")
		}
	})
}

func TestImageHelper(t *testing.T) {
	t.Run("image nil when no image data", func(t *testing.T) {
		input := map[string]any{
			"env": map[string]any{"command": "scan"},
		}
		src := `image == null`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected image to be null when no image data present")
		}
	})

	t.Run("image basic fields from request", func(t *testing.T) {
		input := map[string]any{
			"request": map[string]any{
				"registry":   "ghcr.io",
				"repository": "acme/app",
				"tag":        "v1.0.0",
			},
		}
		src := `image.registry == "ghcr.io" && image.repository == "acme/app" && image.tag == "v1.0.0"`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected image fields to match request data")
		}
	})

	t.Run("image reference defaults to digest or tag", func(t *testing.T) {
		input := map[string]any{
			"request": map[string]any{
				"registry":   "docker.io",
				"repository": "library/alpine",
				"digest":     "sha256:abc123",
			},
		}
		src := `image.reference == "sha256:abc123"`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected image.reference to default to digest")
		}
	})

	t.Run("image.image composite field without tag", func(t *testing.T) {
		input := map[string]any{
			"request": map[string]any{
				"registry":   "ghcr.io",
				"repository": "owner/repo",
			},
		}
		src := `image.image == "ghcr.io/owner/repo"`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected image.image to be registry/repository composite")
		}
	})

	t.Run("image.image includes tag when present", func(t *testing.T) {
		input := map[string]any{
			"request": map[string]any{
				"registry":   "gcr.io",
				"repository": "project/app",
				"tag":        "v1.2.3",
			},
		}
		src := `image.image == "gcr.io/project/app:v1.2.3"`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected image.image to include tag: gcr.io/project/app:v1.2.3")
		}
	})

	t.Run("image.image includes digest when present", func(t *testing.T) {
		input := map[string]any{
			"request": map[string]any{
				"registry":   "docker.io",
				"repository": "library/nginx",
				"digest":     "sha256:abc123def456",
			},
		}
		src := `image.image == "docker.io/library/nginx@sha256:abc123def456"`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected image.image to include digest")
		}
	})

	t.Run("image.image prefers digest over tag", func(t *testing.T) {
		input := map[string]any{
			"request": map[string]any{
				"registry":   "ghcr.io",
				"repository": "owner/app",
				"tag":        "latest",
				"digest":     "sha256:xyz789",
			},
		}
		// Digest should take precedence over tag
		src := `image.image == "ghcr.io/owner/app@sha256:xyz789"`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected image.image to prefer digest over tag")
		}
	})

	t.Run("image from target provenance", func(t *testing.T) {
		input := map[string]any{
			"target": map[string]any{
				"kind": "container-image",
				"provenance": map[string]any{
					"registry":   "registry-1.docker.io",
					"repository": "library/ubuntu",
					"tag":        "22.04",
				},
			},
		}
		src := `image.registry == "registry-1.docker.io" && image.repository == "library/ubuntu"`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected image to be populated from target.provenance")
		}
	})
}

func TestImageConfigHelper(t *testing.T) {
	t.Run("image.config.user", func(t *testing.T) {
		input := map[string]any{
			"request": map[string]any{
				"registry":   "ghcr.io",
				"repository": "acme/app",
			},
			"image_info": map[string]any{
				"config": map[string]any{
					"user":    "app",
					"is_root": false,
				},
			},
		}
		src := `image.config.user == "app" && image.config.is_root == false`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected image.config.user to be 'app' and is_root false")
		}
	})

	t.Run("image.config.is_root for root user", func(t *testing.T) {
		input := map[string]any{
			"request": map[string]any{
				"registry":   "ghcr.io",
				"repository": "acme/app",
			},
			"image_info": map[string]any{
				"config": map[string]any{
					"user":    "",
					"is_root": true,
				},
			},
		}
		src := `image.config.is_root == true`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected image.config.is_root to be true for empty user")
		}
	})

	t.Run("image.config.env", func(t *testing.T) {
		input := map[string]any{
			"request": map[string]any{
				"registry":   "ghcr.io",
				"repository": "acme/app",
			},
			"image_info": map[string]any{
				"config": map[string]any{
					"env": []any{"PATH=/usr/bin", "HOME=/home/app"},
				},
			},
		}
		src := `image.config.env.size() == 2`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected image.config.env to have 2 entries")
		}
	})

	t.Run("image.config.sensitive_env detection", func(t *testing.T) {
		input := map[string]any{
			"request": map[string]any{
				"registry":   "ghcr.io",
				"repository": "acme/app",
			},
			"image_info": map[string]any{
				"config": map[string]any{
					"env":           []any{"PATH=/usr/bin", "DATABASE_PASSWORD=secret"},
					"sensitive_env": []any{"DATABASE_PASSWORD"},
				},
			},
		}
		src := `image.config.sensitive_env.size() > 0`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected image.config.sensitive_env to have entries")
		}
	})

	t.Run("image.config.entrypoint and cmd", func(t *testing.T) {
		input := map[string]any{
			"request": map[string]any{
				"registry":   "ghcr.io",
				"repository": "acme/app",
			},
			"image_info": map[string]any{
				"config": map[string]any{
					"entrypoint": []any{"/app"},
					"cmd":        []any{"serve", "--port=8080"},
				},
			},
		}
		src := `image.config.entrypoint[0] == "/app" && image.config.cmd.size() == 2`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected image.config.entrypoint and cmd to be set")
		}
	})

	t.Run("image.config.exposed_ports", func(t *testing.T) {
		input := map[string]any{
			"request": map[string]any{
				"registry":   "ghcr.io",
				"repository": "acme/app",
			},
			"image_info": map[string]any{
				"config": map[string]any{
					"exposed_ports": []any{"8080/tcp", "443/tcp"},
				},
			},
		}
		src := `image.config.exposed_ports.exists(p, p == "8080/tcp")`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected image.config.exposed_ports to contain 8080/tcp")
		}
	})

	t.Run("image.config.labels", func(t *testing.T) {
		input := map[string]any{
			"request": map[string]any{
				"registry":   "ghcr.io",
				"repository": "acme/app",
			},
			"image_info": map[string]any{
				"config": map[string]any{
					"labels": map[string]any{
						"version":    "1.0.0",
						"maintainer": "team@example.com",
					},
				},
			},
		}
		src := `image.config.labels["version"] == "1.0.0"`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected image.config.labels to contain version")
		}
	})
}

func TestImageMetadataHelper(t *testing.T) {
	t.Run("image.metadata.architecture", func(t *testing.T) {
		input := map[string]any{
			"request": map[string]any{
				"registry":   "ghcr.io",
				"repository": "acme/app",
			},
			"image_info": map[string]any{
				"metadata": map[string]any{
					"architecture": "amd64",
					"os":           "linux",
				},
			},
		}
		src := `image.metadata.architecture == "amd64" && image.metadata.os == "linux"`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected image.metadata.architecture and os to be set")
		}
	})

	t.Run("image.metadata.layer_count and size", func(t *testing.T) {
		input := map[string]any{
			"request": map[string]any{
				"registry":   "ghcr.io",
				"repository": "acme/app",
			},
			"image_info": map[string]any{
				"metadata": map[string]any{
					"layer_count": 12,
					"size":        104857600, // 100MB
				},
			},
		}
		src := `image.metadata.layer_count == 12 && image.metadata.size > 100000000`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected image.metadata.layer_count and size to be set")
		}
	})
}

func TestImageHistoryHelper(t *testing.T) {
	t.Run("image.history entries", func(t *testing.T) {
		input := map[string]any{
			"request": map[string]any{
				"registry":   "ghcr.io",
				"repository": "acme/app",
			},
			"image_info": map[string]any{
				"history": []any{
					map[string]any{
						"created_by":  "FROM alpine:3.19",
						"empty_layer": true,
					},
					map[string]any{
						"created_by":  "RUN apk add curl",
						"empty_layer": false,
					},
				},
			},
		}
		src := `image.history.size() == 2 && image.history[1].created_by.contains("apk add")`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected image.history to have entries with expected content")
		}
	})

	t.Run("image.history command inspection", func(t *testing.T) {
		input := map[string]any{
			"request": map[string]any{
				"registry":   "ghcr.io",
				"repository": "acme/app",
			},
			"image_info": map[string]any{
				"history": []any{
					map[string]any{"created_by": "FROM ubuntu:22.04"},
					map[string]any{"created_by": "RUN apt-get update && apt-get install -y curl"},
					map[string]any{"created_by": "COPY . /app"},
				},
			},
		}
		src := `image.history.exists(h, h.created_by.contains("apt-get install"))`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected image.history to contain apt-get install command")
		}
	})
}

func TestVulnerabilityLayerDetails(t *testing.T) {
	t.Run("layerDetails.inBaseImage", func(t *testing.T) {
		input := map[string]any{
			"vulnerability": map[string]any{
				"id":       "CVE-2024-1234",
				"severity": "HIGH",
				"layerDetails": map[string]any{
					"index":       2,
					"inBaseImage": true,
					"command":     "RUN apt-get install openssl",
				},
			},
		}
		src := `has(vulnerability.layerDetails) && vulnerability.layerDetails.inBaseImage == true`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected vulnerability.layerDetails.inBaseImage to be true")
		}
	})

	t.Run("layerDetails.index", func(t *testing.T) {
		input := map[string]any{
			"vulnerability": map[string]any{
				"id":       "CVE-2024-5678",
				"severity": "CRITICAL",
				"layerDetails": map[string]any{
					"index":       5,
					"inBaseImage": false,
				},
			},
		}
		src := `vulnerability.layerDetails.index > 3 && !vulnerability.layerDetails.inBaseImage`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected layerDetails.index > 3 and not in base image")
		}
	})

	t.Run("layerDetails.command inspection", func(t *testing.T) {
		input := map[string]any{
			"vulnerability": map[string]any{
				"id":       "CVE-2024-9999",
				"severity": "HIGH",
				"package":  "requests",
				"layerDetails": map[string]any{
					"index":       3,
					"command":     "RUN pip install requests==2.28.0",
					"inBaseImage": false,
				},
			},
		}
		src := `vulnerability.layerDetails.command.contains("pip install")`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected layerDetails.command to contain 'pip install'")
		}
	})

	t.Run("layerDetails.diffId and chainId", func(t *testing.T) {
		input := map[string]any{
			"vulnerability": map[string]any{
				"id":       "CVE-2024-0001",
				"severity": "MEDIUM",
				"layerDetails": map[string]any{
					"index":       1,
					"diffId":      "sha256:abc123def456",
					"chainId":     "sha256:xyz789abc",
					"inBaseImage": true,
				},
			},
		}
		src := `vulnerability.layerDetails.diffId.startsWith("sha256:") && vulnerability.layerDetails.chainId.startsWith("sha256:")`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected layerDetails.diffId and chainId to have sha256 prefix")
		}
	})

	t.Run("layerDetails absent for non-container scans", func(t *testing.T) {
		input := map[string]any{
			"vulnerability": map[string]any{
				"id":       "GO-2024-1234",
				"severity": "HIGH",
				"package":  "github.com/example/pkg",
			},
		}
		src := `!has(vulnerability.layerDetails)`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected layerDetails to be absent for non-container vulnerability")
		}
	})
}

func TestContainerLayerPolicyExpressions(t *testing.T) {
	// Test policy expressions similar to container-layer-vulnerability.yaml
	t.Run("base image critical vulns policy", func(t *testing.T) {
		input := map[string]any{
			"vulnerability": map[string]any{
				"id":       "CVE-2024-1234",
				"severity": "CRITICAL",
				"layerDetails": map[string]any{
					"index":       1,
					"inBaseImage": true,
				},
			},
		}
		src := `has(vulnerability.layerDetails) && vulnerability.layerDetails.inBaseImage == true && vulnerability.severity == "CRITICAL"`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected critical base image vulnerability to match")
		}
	})

	t.Run("application layer vulns policy", func(t *testing.T) {
		input := map[string]any{
			"vulnerability": map[string]any{
				"id":       "CVE-2024-5678",
				"severity": "HIGH",
				"layerDetails": map[string]any{
					"index":       8,
					"inBaseImage": false,
					"command":     "COPY --from=builder /app /app",
				},
			},
		}
		src := `has(vulnerability.layerDetails) && vulnerability.layerDetails.inBaseImage == false && vulnerability.severity in ["HIGH", "CRITICAL"]`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected high severity application layer vulnerability to match")
		}
	})

	t.Run("deep layer threshold policy", func(t *testing.T) {
		input := map[string]any{
			"vulnerability": map[string]any{
				"id":       "CVE-2024-0001",
				"severity": "HIGH",
				"layerDetails": map[string]any{
					"index":       1,
					"inBaseImage": true,
				},
			},
		}
		// Policy: flag vulns in early layers (index < 3)
		src := `has(vulnerability.layerDetails) && vulnerability.layerDetails.index < 3 && vulnerability.severity in ["HIGH", "CRITICAL"]`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected early layer vulnerability to match")
		}
	})

	t.Run("apt-get layer detection policy", func(t *testing.T) {
		input := map[string]any{
			"vulnerability": map[string]any{
				"id":       "CVE-2024-APT1",
				"severity": "CRITICAL",
				"package":  "openssl",
				"layerDetails": map[string]any{
					"index":       3,
					"command":     "RUN apt-get update && apt-get install -y openssl curl",
					"inBaseImage": false,
				},
			},
		}
		src := `has(vulnerability.layerDetails) && has(vulnerability.layerDetails.command) && vulnerability.layerDetails.command.contains("apt-get install")`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected apt-get install command to be detected")
		}
	})
}

func TestImagePolicyExpressions(t *testing.T) {
	// Test policy expressions for image config/metadata
	t.Run("deny root user policy", func(t *testing.T) {
		input := map[string]any{
			"request": map[string]any{
				"registry":   "ghcr.io",
				"repository": "acme/app",
			},
			"image_info": map[string]any{
				"config": map[string]any{
					"user":    "",
					"is_root": true,
				},
			},
		}
		src := `image != null && image.config.is_root == true`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected root user image to match policy")
		}
	})

	t.Run("sensitive env warning policy", func(t *testing.T) {
		input := map[string]any{
			"request": map[string]any{
				"registry":   "ghcr.io",
				"repository": "acme/app",
			},
			"image_info": map[string]any{
				"config": map[string]any{
					"sensitive_env": []any{"AWS_SECRET_KEY", "DATABASE_PASSWORD"},
				},
			},
		}
		src := `image != null && has(image.config.sensitive_env) && size(image.config.sensitive_env) > 0`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected sensitive env detection policy to match")
		}
	})

	t.Run("large image warning policy", func(t *testing.T) {
		input := map[string]any{
			"request": map[string]any{
				"registry":   "ghcr.io",
				"repository": "acme/bloated-app",
			},
			"image_info": map[string]any{
				"metadata": map[string]any{
					"size":        1073741824, // 1GB
					"layer_count": 25,
				},
			},
		}
		src := `image != null && image.metadata.size > 500000000`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected large image policy to match")
		}
	})

	t.Run("registry allowlist policy", func(t *testing.T) {
		input := map[string]any{
			"request": map[string]any{
				"registry":   "untrusted-registry.io",
				"repository": "some/image",
			},
		}
		allowedRegistries := []string{"ghcr.io", "gcr.io", "registry-1.docker.io"}
		src := `image != null && !(image.registry in ["ghcr.io", "gcr.io", "registry-1.docker.io"])`
		_ = allowedRegistries // used for documentation
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected untrusted registry to be detected")
		}
	})
}

// TestVulnerabilityGraphFields tests that graph-derived fields (path, depth)
// work correctly in CEL policy expressions.
func TestVulnerabilityGraphFields(t *testing.T) {
	t.Run("depth field with orValue default", func(t *testing.T) {
		// Vulnerability without depth field (no --with-graph)
		input := map[string]any{
			"vulnerability": map[string]any{
				"id":       "CVE-2024-1234",
				"severity": "HIGH",
			},
		}
		src := `vulnerability.?depth.orValue(0) == 0`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected depth to default to 0 when not present")
		}
	})

	t.Run("depth field present", func(t *testing.T) {
		// Vulnerability with depth (from --with-graph)
		input := map[string]any{
			"vulnerability": map[string]any{
				"id":       "CVE-2024-1234",
				"severity": "CRITICAL",
				"depth":    2,
			},
		}
		src := `vulnerability.?depth.orValue(0) == 2`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected depth to be 2")
		}
	})

	t.Run("path field with orValue default", func(t *testing.T) {
		// Vulnerability without path field
		input := map[string]any{
			"vulnerability": map[string]any{
				"id":       "CVE-2024-1234",
				"severity": "HIGH",
			},
		}
		src := `vulnerability.?path.orValue([]).size() == 0`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected path to default to empty list")
		}
	})

	t.Run("path field present", func(t *testing.T) {
		// Vulnerability with path (from --with-graph)
		input := map[string]any{
			"vulnerability": map[string]any{
				"id":       "CVE-2024-1234",
				"severity": "CRITICAL",
				"path":     []any{"myapp", "go-git/v5", "x/crypto"},
				"depth":    2,
			},
		}
		src := `vulnerability.?path.orValue([]).size() == 3`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected path to have 3 elements")
		}
	})

	t.Run("path contains check", func(t *testing.T) {
		input := map[string]any{
			"vulnerability": map[string]any{
				"id":       "CVE-2024-1234",
				"severity": "HIGH",
				"path":     []any{"myapp", "legacy-lib", "x/crypto"},
				"depth":    2,
			},
		}
		src := `vulnerability.?path.orValue([]).exists(p, p.contains("legacy"))`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected path to contain 'legacy'")
		}
	})

	t.Run("combined depth and severity policy", func(t *testing.T) {
		// Policy: block critical vulnerabilities in direct deps (depth == 0)
		input := map[string]any{
			"vulnerability": map[string]any{
				"id":       "CVE-2024-1234",
				"severity": "CRITICAL",
				"depth":    0,
			},
		}
		src := `vulnerability.severity == "CRITICAL" && vulnerability.?depth.orValue(0) == 0`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected policy to match critical direct dependency")
		}
	})

	t.Run("allow deep transitive medium severity", func(t *testing.T) {
		// Policy: allow medium severity if depth > 3
		input := map[string]any{
			"vulnerability": map[string]any{
				"id":       "CVE-2024-5678",
				"severity": "MEDIUM",
				"depth":    4,
			},
		}
		src := `vulnerability.severity == "MEDIUM" && vulnerability.?depth.orValue(0) > 3`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected policy to match deep transitive medium vulnerability")
		}
	})

	t.Run("vulnerabilities list with depth filter", func(t *testing.T) {
		// Report-level policy: count deep transitive vulnerabilities
		input := map[string]any{
			"vulnerabilities": []any{
				map[string]any{"id": "CVE-1", "severity": "HIGH", "depth": 1},
				map[string]any{"id": "CVE-2", "severity": "MEDIUM", "depth": 4},
				map[string]any{"id": "CVE-3", "severity": "LOW", "depth": 5},
			},
		}
		src := `vulnerabilities.filter(v, v.?depth.orValue(0) > 3).size() == 2`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected 2 deep transitive vulnerabilities")
		}
	})
}
