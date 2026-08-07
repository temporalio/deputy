package sbomx

import (
	"testing"

	pb "deps.dev/api/v3"
	"github.com/google/osv-scalibr/purl"
	"github.com/protobom/protobom/pkg/sbom"
)

func TestGenerateCPE(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		purl      *purl.PackageURL
		pkgName   string
		version   string
		wantCPE   string
		wantEmpty bool
	}{
		{
			name: "Go module with github.com prefix",
			purl: &purl.PackageURL{
				Type:      "golang",
				Namespace: "github.com/kubernetes",
				Name:      "kubernetes",
				Version:   "v1.28.0",
			},
			pkgName: "kubernetes",
			version: "v1.28.0",
			wantCPE: "cpe:2.3:a:kubernetes:kubernetes:v1.28.0:*:*:*:*:go:*:*",
		},
		{
			name: "npm scoped package",
			purl: &purl.PackageURL{
				Type:      "npm",
				Namespace: "@angular",
				Name:      "core",
				Version:   "16.0.0",
			},
			pkgName: "core",
			version: "16.0.0",
			wantCPE: "cpe:2.3:a:angular:core:16.0.0:*:*:*:*:node.js:*:*",
		},
		{
			name: "npm unscoped package",
			purl: &purl.PackageURL{
				Type:    "npm",
				Name:    "lodash",
				Version: "4.17.21",
			},
			pkgName: "lodash",
			version: "4.17.21",
			wantCPE: "cpe:2.3:a:lodash:lodash:4.17.21:*:*:*:*:node.js:*:*",
		},
		{
			name: "PyPI package",
			purl: &purl.PackageURL{
				Type:    "pypi",
				Name:    "requests",
				Version: "2.31.0",
			},
			pkgName: "requests",
			version: "2.31.0",
			wantCPE: "cpe:2.3:a:requests:requests:2.31.0:*:*:*:*:python:*:*",
		},
		{
			name: "Maven package",
			purl: &purl.PackageURL{
				Type:      "maven",
				Namespace: "org.apache.logging.log4j",
				Name:      "log4j-core",
				Version:   "2.20.0",
			},
			pkgName: "log4j-core",
			version: "2.20.0",
			wantCPE: "cpe:2.3:a:org.apache.logging.log4j:log4j-core:2.20.0:*:*:*:*:java:*:*",
		},
		{
			name: "Cargo package",
			purl: &purl.PackageURL{
				Type:    "cargo",
				Name:    "serde",
				Version: "1.0.163",
			},
			pkgName: "serde",
			version: "1.0.163",
			wantCPE: "cpe:2.3:a:serde:serde:1.0.163:*:*:*:*:rust:*:*",
		},
		{
			name:      "nil PURL",
			purl:      nil,
			pkgName:   "test",
			version:   "1.0.0",
			wantEmpty: true,
		},
		{
			name:    "mise registry-backed tool delegates to underlying artifact",
			purl:    &purl.PackageURL{Type: "mise", Name: "npm:prettier", Version: "3.0.0"},
			pkgName: "npm:prettier",
			version: "3.0.0",
			wantCPE: "cpe:2.3:a:prettier:prettier:3.0.0:*:*:*:*:node.js:*:*",
		},
		{
			name:      "mise ubi release tool emits no fabricated CPE",
			purl:      &purl.PackageURL{Type: "mise", Name: "ubi:cli/cli", Version: "2.0.0"},
			pkgName:   "ubi:cli/cli",
			version:   "2.0.0",
			wantEmpty: true,
		},
		{
			name:      "mise github release tool emits no fabricated CPE",
			purl:      &purl.PackageURL{Type: "mise", Name: "github:owner/repo", Version: "1.0.0"},
			pkgName:   "github:owner/repo",
			version:   "1.0.0",
			wantEmpty: true,
		},
		{
			name:      "mise core runtime emits no fabricated CPE",
			purl:      &purl.PackageURL{Type: "mise", Name: "node", Version: "20.0.0"},
			pkgName:   "node",
			version:   "20.0.0",
			wantEmpty: true,
		},
		{
			name: "empty version uses wildcard",
			purl: &purl.PackageURL{
				Type:    "npm",
				Name:    "test",
				Version: "",
			},
			pkgName: "test",
			version: "",
			wantCPE: "cpe:2.3:a:test:test:*:*:*:*:*:node.js:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := generateCPE(tt.purl, tt.pkgName, tt.version)
			if tt.wantEmpty {
				if got != "" {
					t.Errorf("generateCPE() = %q, want empty", got)
				}
				return
			}
			if got != tt.wantCPE {
				t.Errorf("generateCPE() = %q, want %q", got, tt.wantCPE)
			}
		})
	}
}

func TestSanitizeCPEField(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  string
	}{
		{"simple", "simple"},
		{"WITH_CAPS", "with_caps"},
		{"has spaces", "has_spaces"},
		{"has/slashes", "has_slashes"},
		{"has:colons", "has_colons"},
		{"@scoped", "scoped"},
		{"version-1.0.0", "version-1.0.0"},
		{"valid_underscore", "valid_underscore"},
		{"has.dots", "has.dots"},
		{"inv@lid#chars!", "invlidchars"},
		{"", ""},
		{"  trimmed  ", "trimmed"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()
			got := sanitizeCPEField(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeCPEField(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestLinkLabelToExternalRefType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		label string
		want  sbom.ExternalReference_ExternalReferenceType
	}{
		{"SOURCE", sbom.ExternalReference_VCS},
		{"Repository", sbom.ExternalReference_VCS},
		{"GitHub", sbom.ExternalReference_VCS},
		{"homepage", sbom.ExternalReference_WEBSITE},
		{"Home Page", sbom.ExternalReference_WEBSITE},
		{"Bug Tracker", sbom.ExternalReference_ISSUE_TRACKER},
		{"Issues", sbom.ExternalReference_ISSUE_TRACKER},
		{"Documentation", sbom.ExternalReference_DOCUMENTATION},
		{"Docs", sbom.ExternalReference_DOCUMENTATION},
		{"Changelog", sbom.ExternalReference_RELEASE_NOTES},
		{"Release Notes", sbom.ExternalReference_RELEASE_NOTES},
		{"License", sbom.ExternalReference_LICENSE},
		{"Download", sbom.ExternalReference_DOWNLOAD},
		{"Registry", sbom.ExternalReference_DOWNLOAD},
		{"Security Advisory", sbom.ExternalReference_SECURITY_ADVISORY},
		{"Unknown Label", sbom.ExternalReference_OTHER},
		{"", sbom.ExternalReference_OTHER},
	}

	for _, tt := range tests {
		t.Run(tt.label, func(t *testing.T) {
			t.Parallel()
			got := linkLabelToExternalRefType(tt.label)
			if got != tt.want {
				t.Errorf("linkLabelToExternalRefType(%q) = %v, want %v", tt.label, got, tt.want)
			}
		})
	}
}

func TestExtractOwnerFromProjectID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		projectID string
		want      string
	}{
		{"github.com/kubernetes/kubernetes", "kubernetes"},
		{"gitlab.com/gitlab-org/gitlab", "gitlab-org"},
		{"bitbucket.org/atlassian/stash", "atlassian"},
		{"example.com/owner", "example.com"},
		{"single", ""}, // single word without "/" is not a valid project ID format
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.projectID, func(t *testing.T) {
			t.Parallel()
			got := extractOwnerFromProjectID(tt.projectID)
			if got != tt.want {
				t.Errorf("extractOwnerFromProjectID(%q) = %q, want %q", tt.projectID, got, tt.want)
			}
		})
	}
}

func TestAddCPEToNode(t *testing.T) {
	t.Parallel()

	t.Run("adds CPE to node without one", func(t *testing.T) {
		t.Parallel()
		node := &sbom.Node{
			Name:    "lodash",
			Version: "4.17.21",
			Identifiers: map[int32]string{
				int32(sbom.SoftwareIdentifierType_PURL): "pkg:npm/lodash@4.17.21",
			},
		}

		added := addCPEToNode(node)
		if !added {
			t.Error("expected CPE to be added")
		}

		cpe, ok := node.Identifiers[int32(sbom.SoftwareIdentifierType_CPE23)]
		if !ok {
			t.Fatal("expected CPE23 identifier to exist")
		}
		if cpe == "" {
			t.Error("expected non-empty CPE")
		}
		t.Logf("Generated CPE: %s", cpe)
	})

	t.Run("does not overwrite existing CPE", func(t *testing.T) {
		t.Parallel()
		existingCPE := "cpe:2.3:a:existing:existing:1.0:*:*:*:*:*:*:*"
		node := &sbom.Node{
			Name:    "test",
			Version: "1.0.0",
			Identifiers: map[int32]string{
				int32(sbom.SoftwareIdentifierType_PURL):  "pkg:npm/test@1.0.0",
				int32(sbom.SoftwareIdentifierType_CPE23): existingCPE,
			},
		}

		added := addCPEToNode(node)
		if added {
			t.Error("should not add CPE when one already exists")
		}

		cpe := node.Identifiers[int32(sbom.SoftwareIdentifierType_CPE23)]
		if cpe != existingCPE {
			t.Errorf("CPE was modified: got %q, want %q", cpe, existingCPE)
		}
	})

	t.Run("handles nil node", func(t *testing.T) {
		t.Parallel()
		added := addCPEToNode(nil)
		if added {
			t.Error("should return false for nil node")
		}
	})

	t.Run("handles node without PURL", func(t *testing.T) {
		t.Parallel()
		node := &sbom.Node{
			Name:    "test",
			Version: "1.0.0",
		}
		added := addCPEToNode(node)
		if added {
			t.Error("should return false for node without PURL")
		}
	})
}

func TestDetectHashAlgorithm(t *testing.T) {
	t.Parallel()

	tests := []struct {
		hash string
		want sbom.HashAlgorithm
	}{
		// SHA256 (64 hex chars)
		{"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", sbom.HashAlgorithm_SHA256},
		{"E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855", sbom.HashAlgorithm_SHA256},
		// SHA1 (40 hex chars)
		{"da39a3ee5e6b4b0d3255bfef95601890afd80709", sbom.HashAlgorithm_SHA1},
		// MD5 (32 hex chars)
		{"d41d8cd98f00b204e9800998ecf8427e", sbom.HashAlgorithm_MD5},
		// Invalid/unknown
		{"tooshort", sbom.HashAlgorithm_UNKNOWN},
		{"", sbom.HashAlgorithm_UNKNOWN},
		{"not-a-hex-string-but-64-chars-long-xxxxxxxxxxxxxxxxxxxxxxxxx", sbom.HashAlgorithm_UNKNOWN},
	}

	for _, tt := range tests {
		t.Run(tt.hash, func(t *testing.T) {
			t.Parallel()
			got := DetectHashAlgorithm(tt.hash)
			if got != tt.want {
				t.Errorf("DetectHashAlgorithm(%q) = %v, want %v", tt.hash, got, tt.want)
			}
		})
	}
}

func TestCalculateCompleteness(t *testing.T) {
	t.Parallel()

	t.Run("empty document", func(t *testing.T) {
		t.Parallel()
		score := CalculateCompleteness(nil)
		if score.TotalComponents != 0 {
			t.Errorf("expected 0 components, got %d", score.TotalComponents)
		}
	})

	t.Run("complete document", func(t *testing.T) {
		t.Parallel()
		doc := &sbom.Document{
			Metadata: &sbom.Metadata{
				Tools: []*sbom.Tool{{Name: "deputy", Version: "1.0.0"}},
			},
			NodeList: &sbom.NodeList{
				Nodes: []*sbom.Node{
					{
						Id:   "root",
						Type: sbom.Node_PACKAGE,
						Name: "app",
					},
					{
						Id:      "pkg:npm/lodash@4.17.21",
						Type:    sbom.Node_PACKAGE,
						Name:    "lodash",
						Version: "4.17.21",
						Identifiers: map[int32]string{
							int32(sbom.SoftwareIdentifierType_PURL):  "pkg:npm/lodash@4.17.21",
							int32(sbom.SoftwareIdentifierType_CPE23): "cpe:2.3:a:lodash:lodash:4.17.21:*:*:*:*:*:*:*",
						},
						Licenses:  []string{"MIT"},
						Hashes:    map[int32]string{int32(sbom.HashAlgorithm_SHA256): "abc123"},
						Suppliers: []*sbom.Person{{Name: "lodash"}},
						ExternalReferences: []*sbom.ExternalReference{
							{Url: "https://github.com/lodash/lodash", Type: sbom.ExternalReference_VCS},
						},
					},
				},
				RootElements: []string{"root"},
			},
		}

		score := CalculateCompleteness(doc)
		if score.TotalComponents != 1 {
			t.Errorf("expected 1 component, got %d", score.TotalComponents)
		}
		if score.Score < 0.9 {
			t.Errorf("expected high completeness score, got %.2f", score.Score)
		}
		if score.ComponentsWithPURL != 1 {
			t.Errorf("expected 1 component with PURL, got %d", score.ComponentsWithPURL)
		}
		if score.ComponentsWithHash != 1 {
			t.Errorf("expected 1 component with hash, got %d", score.ComponentsWithHash)
		}
		if score.ComponentsWithCPE != 1 {
			t.Errorf("expected 1 component with CPE, got %d", score.ComponentsWithCPE)
		}
	})

	t.Run("incomplete document", func(t *testing.T) {
		t.Parallel()
		doc := &sbom.Document{
			NodeList: &sbom.NodeList{
				Nodes: []*sbom.Node{
					{
						Id:   "root",
						Type: sbom.Node_PACKAGE,
						Name: "app",
					},
					{
						Id:      "pkg:npm/lodash@4.17.21",
						Type:    sbom.Node_PACKAGE,
						Name:    "lodash",
						Version: "4.17.21",
						// Missing: identifiers, licenses, hashes, suppliers, external refs
					},
				},
				RootElements: []string{"root"},
			},
		}

		score := CalculateCompleteness(doc)
		if score.Score > 0.5 {
			t.Errorf("expected low completeness score for incomplete doc, got %.2f", score.Score)
		}
		if score.NTIACompliant {
			t.Error("incomplete document should not be NTIA compliant")
		}
		if len(score.NTIAMissing) == 0 {
			t.Error("expected missing NTIA elements to be listed")
		}
		t.Logf("NTIA missing: %v", score.NTIAMissing)
	})
}

func TestBuildPURLFromVersionKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		vk   *pb.VersionKey
		want string
	}{
		{
			name: "nil version key",
			vk:   nil,
			want: "",
		},
		{
			name: "Go module",
			vk: &pb.VersionKey{
				System:  pb.System_GO,
				Name:    "github.com/example/pkg",
				Version: "v1.2.3",
			},
			want: "pkg:golang/github.com/example/pkg@v1.2.3",
		},
		{
			name: "npm package",
			vk: &pb.VersionKey{
				System:  pb.System_NPM,
				Name:    "lodash",
				Version: "4.17.21",
			},
			want: "pkg:npm/lodash@4.17.21",
		},
		{
			name: "Maven package",
			vk: &pb.VersionKey{
				System:  pb.System_MAVEN,
				Name:    "org.apache.logging.log4j:log4j-core",
				Version: "2.20.0",
			},
			want: "pkg:maven/org.apache.logging.log4j/log4j-core@2.20.0",
		},
		{
			name: "PyPI package",
			vk: &pb.VersionKey{
				System:  pb.System_PYPI,
				Name:    "requests",
				Version: "2.31.0",
			},
			want: "pkg:pypi/requests@2.31.0",
		},
		{
			name: "Cargo package",
			vk: &pb.VersionKey{
				System:  pb.System_CARGO,
				Name:    "serde",
				Version: "1.0.163",
			},
			want: "pkg:cargo/serde@1.0.163",
		},
		{
			name: "unsupported system",
			vk: &pb.VersionKey{
				System:  pb.System_SYSTEM_UNSPECIFIED,
				Name:    "unknown",
				Version: "1.0.0",
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := buildPURLFromVersionKey(tt.vk)
			if got != tt.want {
				t.Errorf("buildPURLFromVersionKey() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestEnrichDependencyEdges_nilHandling(t *testing.T) {
	t.Parallel()

	t.Run("nil document", func(t *testing.T) {
		t.Parallel()
		count, err := enrichDependencyEdges(t.Context(), nil, nil, 10)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if count != 0 {
			t.Errorf("expected 0 edges, got %d", count)
		}
	})

	t.Run("empty document", func(t *testing.T) {
		t.Parallel()
		doc := &sbom.Document{}
		count, err := enrichDependencyEdges(t.Context(), nil, doc, 10)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if count != 0 {
			t.Errorf("expected 0 edges, got %d", count)
		}
	})
}

func TestEnrichOptions_AddDependencies(t *testing.T) {
	t.Parallel()

	// Default should have AddDependencies disabled
	opts := DefaultEnrichOptions()
	if opts.AddDependencies {
		t.Error("expected AddDependencies to be false by default")
	}

	// All other enrichments should be enabled
	if !opts.AddCPEs {
		t.Error("expected AddCPEs to be true by default")
	}
	if !opts.AddSuppliers {
		t.Error("expected AddSuppliers to be true by default")
	}
	if !opts.AddExternalRefs {
		t.Error("expected AddExternalRefs to be true by default")
	}
}

func TestAddHashesToNode(t *testing.T) {
	t.Parallel()

	t.Run("adds hash to node", func(t *testing.T) {
		t.Parallel()
		node := &sbom.Node{Name: "test"}
		hash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

		added := AddHashesToNode(node, sbom.HashAlgorithm_SHA256, hash)
		if !added {
			t.Error("expected hash to be added")
		}
		if node.Hashes[int32(sbom.HashAlgorithm_SHA256)] != hash {
			t.Errorf("hash not stored correctly")
		}
	})

	t.Run("does not overwrite existing hash", func(t *testing.T) {
		t.Parallel()
		existingHash := "existing"
		node := &sbom.Node{
			Name:   "test",
			Hashes: map[int32]string{int32(sbom.HashAlgorithm_SHA256): existingHash},
		}

		added := AddHashesToNode(node, sbom.HashAlgorithm_SHA256, "newhash")
		if added {
			t.Error("should not overwrite existing hash")
		}
		if node.Hashes[int32(sbom.HashAlgorithm_SHA256)] != existingHash {
			t.Error("existing hash was modified")
		}
	})

	t.Run("handles nil node", func(t *testing.T) {
		t.Parallel()
		added := AddHashesToNode(nil, sbom.HashAlgorithm_SHA256, "hash")
		if added {
			t.Error("should return false for nil node")
		}
	})

	t.Run("handles empty hash", func(t *testing.T) {
		t.Parallel()
		node := &sbom.Node{Name: "test"}
		added := AddHashesToNode(node, sbom.HashAlgorithm_SHA256, "")
		if added {
			t.Error("should return false for empty hash")
		}
	})
}
