package policy

import (
	"testing"

	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	policyv1 "github.com/temporalio/deputy/gen/deputy/policy/v1"
	scanv1 "github.com/temporalio/deputy/gen/deputy/scan/v1"
	targetv1 "github.com/temporalio/deputy/gen/deputy/target/v1"
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
	// Proto-first: Tests pass pkg directly in the input map.
	// The typed PolicyInput protos (e.g., ScanVulnerabilityPolicyInput) have pkg as a first-class field.
	tests := []struct {
		name     string
		input    map[string]any
		expected string // expected pkg.name
	}{
		{
			name: "pkg from package proto",
			input: map[string]any{
				"pkg": &dependencyv1.Package{Name: "test-pkg", Version: "1.0.0"},
			},
			expected: "test-pkg",
		},
		{
			name: "pkg with component also present",
			input: map[string]any{
				"pkg":       &dependencyv1.Package{Name: "pkg-name"},
				"component": &dependencyv1.Package{Name: "comp-pkg"},
			},
			expected: "pkg-name",
		},
		{
			name: "pkg with request also present",
			input: map[string]any{
				"pkg":     &dependencyv1.Package{Name: "pkg-name"},
				"request": &policyv1.ProxyRequest{Package: "req-pkg"},
			},
			expected: "pkg-name",
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
	// Proto-first: Tests pass pkg directly in the input map.
	// Tests verify that Package proto fields have expected default values.
	t.Run("licenses defaults to empty list", func(t *testing.T) {
		input := map[string]any{
			"pkg": &dependencyv1.Package{Name: "test-pkg"},
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
			"pkg": &dependencyv1.Package{Name: "test-pkg"},
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
			"pkg": &dependencyv1.Package{Name: "test-pkg"},
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
			"pkg": &dependencyv1.Package{Name: "test-pkg"},
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
			"pkg": &dependencyv1.Package{
				Name:      "test-pkg",
				Version:   "1.2.3",
				Ecosystem: "npm",
				Licenses:  []string{"MIT", "Apache-2.0"},
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
			"pkg": &dependencyv1.Package{Name: "test-pkg"},
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

	t.Run("pkg with all defaults", func(t *testing.T) {
		// Empty package proto should have empty fields
		input := map[string]any{
			"pkg": &dependencyv1.Package{},
		}
		src := `pkg.name == "" && pkg.version == "" && pkg.ecosystem == "" && pkg.licenses.size() == 0`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected pkg to have all empty defaults")
		}
	})

	t.Run("name defaults to empty string with empty package", func(t *testing.T) {
		// Empty package proto should have empty name
		input := map[string]any{
			"pkg": &dependencyv1.Package{Licenses: []string{"MIT"}},
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
	// Proto-first: image is passed directly as containerv1.ImageInfo.
	// Image provenance (registry, repository, tag) is accessed via target.provenance.

	t.Run("image nil when not provided", func(t *testing.T) {
		// Proto-first: when image is not provided, it's a null value.
		// Use optional types to check: image.?config returns optional empty.
		input := map[string]any{
			"image": nil, // Explicitly null
			"env":   &policyv1.Environment{Command: "scan"},
		}
		// Check that image is null/empty using CEL optional chaining
		src := `image == null`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected image == null to be true when nil")
		}
	})

	t.Run("target.provenance for image registry/repository", func(t *testing.T) {
		input := map[string]any{
			"target": &targetv1.Target{
				Kind:        targetv1.TargetKind_TARGET_KIND_CONTAINER_IMAGE,
				DisplayPath: "ghcr.io/acme/app:v1.0.0",
				Provenance: map[string]string{
					"registry":   "ghcr.io",
					"repository": "acme/app",
					"tag":        "v1.0.0",
				},
			},
		}
		src := `target.provenance["registry"] == "ghcr.io" && target.provenance["repository"] == "acme/app"`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected target.provenance to contain registry and repository")
		}
	})

	t.Run("target.display_path for image reference", func(t *testing.T) {
		input := map[string]any{
			"target": &targetv1.Target{
				Kind:        targetv1.TargetKind_TARGET_KIND_CONTAINER_IMAGE,
				DisplayPath: "ghcr.io/owner/repo:v1.2.3",
			},
		}
		src := `target.display_path == "ghcr.io/owner/repo:v1.2.3"`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected target.display_path to contain image reference")
		}
	})

	t.Run("target.reference for image reference", func(t *testing.T) {
		input := map[string]any{
			"target": &targetv1.Target{
				Kind:        targetv1.TargetKind_TARGET_KIND_CONTAINER_IMAGE,
				Reference:   "gcr.io/project/app:v1.2.3",
				DisplayPath: "gcr.io/project/app:v1.2.3",
			},
		}
		src := `target.reference == "gcr.io/project/app:v1.2.3"`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected target.reference to contain image reference")
		}
	})

	t.Run("target.provenance for digest", func(t *testing.T) {
		input := map[string]any{
			"target": &targetv1.Target{
				Kind: targetv1.TargetKind_TARGET_KIND_CONTAINER_IMAGE,
				Provenance: map[string]string{
					"registry":   "docker.io",
					"repository": "library/nginx",
					"digest":     "sha256:abc123def456",
				},
			},
		}
		src := `target.provenance["digest"] == "sha256:abc123def456"`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected target.provenance to contain digest")
		}
	})
}

func TestImageConfigHelper(t *testing.T) {
	// Proto-first: image is passed directly as scanv1.ImageInfo.
	t.Run("image.config.user", func(t *testing.T) {
		input := map[string]any{
			"image": &scanv1.ImageInfo{
				Config: &scanv1.ImageConfig{
					User:   "app",
					IsRoot: false,
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
			"image": &scanv1.ImageInfo{
				Config: &scanv1.ImageConfig{
					User:   "",
					IsRoot: true,
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
			"image": &scanv1.ImageInfo{
				Config: &scanv1.ImageConfig{
					Env: []string{"PATH=/usr/bin", "HOME=/home/app"},
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
			"image": &scanv1.ImageInfo{
				Config: &scanv1.ImageConfig{
					Env:          []string{"PATH=/usr/bin", "DATABASE_PASSWORD=secret"},
					SensitiveEnv: []string{"DATABASE_PASSWORD"},
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
			"image": &scanv1.ImageInfo{
				Config: &scanv1.ImageConfig{
					Entrypoint: []string{"/app"},
					Cmd:        []string{"serve", "--port=8080"},
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
			"image": &scanv1.ImageInfo{
				Config: &scanv1.ImageConfig{
					ExposedPorts: []string{"8080/tcp", "443/tcp"},
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
			"image": &scanv1.ImageInfo{
				Config: &scanv1.ImageConfig{
					Labels: map[string]string{
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
	// Proto-first: image is passed directly as scanv1.ImageInfo.
	t.Run("image.metadata.architecture", func(t *testing.T) {
		input := map[string]any{
			"image": &scanv1.ImageInfo{
				Metadata: &scanv1.ImageMetadata{
					Architecture: "amd64",
					Os:           "linux",
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
			"image": &scanv1.ImageInfo{
				Metadata: &scanv1.ImageMetadata{
					LayerCount: 12,
					Size:       104857600, // 100MB
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
	// Proto-first: image is passed directly as scanv1.ImageInfo.
	t.Run("image.history entries", func(t *testing.T) {
		input := map[string]any{
			"image": &scanv1.ImageInfo{
				History: []*scanv1.HistoryEntry{
					{CreatedBy: "FROM alpine:3.19", EmptyLayer: true},
					{CreatedBy: "RUN apk add curl", EmptyLayer: false},
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
			"image": &scanv1.ImageInfo{
				History: []*scanv1.HistoryEntry{
					{CreatedBy: "FROM ubuntu:22.04"},
					{CreatedBy: "RUN apt-get update && apt-get install -y curl"},
					{CreatedBy: "COPY . /app"},
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
			"target": &targetv1.Target{
				Kind:        targetv1.TargetKind_TARGET_KIND_CONTAINER_IMAGE,
				DisplayPath: "ghcr.io/acme/app:v1.0.0",
			},
			"image": &scanv1.ImageInfo{
				Config: &scanv1.ImageConfig{
					User:   "",
					IsRoot: true,
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
			"target": &targetv1.Target{
				Kind:        targetv1.TargetKind_TARGET_KIND_CONTAINER_IMAGE,
				DisplayPath: "ghcr.io/acme/app:v1.0.0",
			},
			"image": &scanv1.ImageInfo{
				Config: &scanv1.ImageConfig{
					SensitiveEnv: []string{"AWS_SECRET_KEY", "DATABASE_PASSWORD"},
				},
			},
		}
		src := `image != null && size(image.config.sensitive_env) > 0`
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
			"target": &targetv1.Target{
				Kind:        targetv1.TargetKind_TARGET_KIND_CONTAINER_IMAGE,
				DisplayPath: "ghcr.io/acme/bloated-app:v1.0.0",
			},
			"image": &scanv1.ImageInfo{
				Metadata: &scanv1.ImageMetadata{
					Size:       1073741824, // 1GB
					LayerCount: 25,
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
		// Proto-first: registry info comes from target.provenance, not image
		input := map[string]any{
			"target": &targetv1.Target{
				Kind:        targetv1.TargetKind_TARGET_KIND_CONTAINER_IMAGE,
				DisplayPath: "untrusted-registry.io/some/image:v1.0.0",
				Provenance: map[string]string{
					"registry":   "untrusted-registry.io",
					"repository": "some/image",
				},
			},
		}
		allowedRegistries := []string{"ghcr.io", "gcr.io", "registry-1.docker.io"}
		// Use map indexing with "in" for provenance check (has() only works on proto fields)
		src := `"registry" in target.provenance && !(target.provenance["registry"] in ["ghcr.io", "gcr.io", "registry-1.docker.io"])`
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
