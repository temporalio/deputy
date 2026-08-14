package proto

import (
	"testing"

	"github.com/google/osv-scalibr/extractor"

	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	"github.com/temporalio/deputy/internal/compare"
	"github.com/temporalio/deputy/internal/purlx"
	"github.com/temporalio/deputy/internal/repository/workspace"
)

// TestDirectKeysSurviveTheManifestRoundTrip drives the real contract between
// the two halves of directness classification: the manifest a project ships is
// read by compare.CollectDirectDependenciesFromWorkspace, and the package an
// extractor reports is looked up by ExtractorPackageIsDirect. A key either
// side folds differently is a dependency silently reported as transitive, so
// the assertion is end to end rather than on either normalizer alone (the
// rules themselves are covered in internal/ecosystem).
func TestDirectKeysSurviveTheManifestRoundTrip(t *testing.T) {
	tests := []struct {
		name     string
		manifest string
		contents string
		pkg      *extractor.Package
		want     bool
	}{
		{
			name:     "cargo separator folding",
			manifest: "Cargo.toml",
			contents: "[dependencies]\nserde-json = \"1.0\"\n",
			pkg:      &extractor.Package{Name: "serde_json", Version: "1.0.117", PURLType: "cargo"},
			want:     true,
		},
		{
			name:     "cargo renamed dependency",
			manifest: "Cargo.toml",
			contents: "[dependencies]\nmy-serde = { package = \"serde\", version = \"1.0\" }\n",
			pkg:      &extractor.Package{Name: "serde", Version: "1.0.203", PURLType: "cargo"},
			want:     true,
		},
		{
			name:     "cargo renamed dependency under its manifest key",
			manifest: "Cargo.toml",
			contents: "[dependencies]\nmy-serde = { package = \"serde\", version = \"1.0\" }\n",
			pkg:      &extractor.Package{Name: "my-serde", Version: "1.0.203", PURLType: "cargo"},
			want:     true,
		},
		{
			name:     "npm aliased dependency",
			manifest: "package.json",
			contents: `{"dependencies":{"my-lodash":"npm:lodash@^4.17.21"}}`,
			pkg:      &extractor.Package{Name: "lodash", Version: "4.17.21", PURLType: "npm"},
			want:     true,
		},
		{
			name:     "cargo transitive crate stays transitive",
			manifest: "Cargo.toml",
			contents: "[dependencies]\nserde = \"1.0\"\n",
			pkg:      &extractor.Package{Name: "syn", Version: "2.0.0", PURLType: "cargo"},
			want:     false,
		},
		{
			// A dotted distribution has to be quoted, since TOML reads a bare
			// dotted key as a nested table and Poetry would not read the
			// unquoted form as a constraint either.
			name:     "pypi poetry dotted distribution",
			manifest: "pyproject.toml",
			contents: "[tool.poetry.dependencies]\npython = \"^3.9\"\n\"zope.interface\" = \"^5.4\"\n",
			pkg:      &extractor.Package{Name: "zope.interface", Version: "5.4.0", PURLType: "pypi"},
			want:     true,
		},
		{
			name:     "pypi poetry mixed case and hyphens",
			manifest: "pyproject.toml",
			contents: "[tool.poetry.dependencies]\nFlask-SQLAlchemy = \"^3.0\"\n",
			pkg:      &extractor.Package{Name: "flask_sqlalchemy", Version: "3.0.5", PURLType: "pypi"},
			want:     true,
		},
		{
			name:     "pypi pep 508 direct reference",
			manifest: "pyproject.toml",
			contents: "[project]\ndependencies = [\"my-pkg @ git+https://example.com/my-pkg.git\"]\n",
			pkg:      &extractor.Package{Name: "my_pkg", Version: "1.0.0", PURLType: "pypi"},
			want:     true,
		},
		{
			name:     "pypi requirements dotted distribution",
			manifest: "requirements.txt",
			contents: "zope.interface==5.4.0\n",
			pkg:      &extractor.Package{Name: "zope-interface", Version: "5.4.0", PURLType: "pypi"},
			want:     true,
		},
		{
			name:     "npm names are not folded",
			manifest: "package.json",
			contents: `{"dependencies":{"left-pad":"^1.3.0"}}`,
			pkg:      &extractor.Package{Name: "left_pad", Version: "1.3.0", PURLType: "npm"},
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ws := workspace.NewMemory()
			t.Cleanup(func() { _ = ws.Close() })
			if err := ws.WriteFile(tt.manifest, []byte(tt.contents), 0o644); err != nil {
				t.Fatalf("write %s: %v", tt.manifest, err)
			}
			direct := compare.CollectDirectDependenciesFromWorkspace(ws)
			if got := ExtractorPackageIsDirect(tt.pkg, direct); got != tt.want {
				t.Errorf("ExtractorPackageIsDirect(%q) = %v, want %v (collected %v)", tt.pkg.Name, got, tt.want, direct)
			}
		})
	}
}

// TestNpmDuplicateVersionsClassifySeparately pins the case a name-only lookup
// gets wrong. npm nests a version that conflicts with the root's, so one
// lockfile carries two copies of a declared package; the extractor reports both
// under one name and discards the install path that distinguished them, so
// directness has to come from the version the declaration resolved to.
//
// Both directions are asserted, because the two failure modes are opposite and a
// fix for one is a plausible cause of the other: the declared copy must stay
// direct, and the nested copy must not be direct even though a direct package of
// the same name exists. The unlocked case is asserted alongside them, since a
// project with no committed lockfile has no resolution to prefer and must keep
// classifying by name.
func TestNpmDuplicateVersionsClassifySeparately(t *testing.T) {
	const manifest = `{"name":"app","dependencies":{"lodash":"^4.17.21","legacy-thing":"^1.0.0"}}`
	const lockfile = `{
  "name": "app",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "app", "dependencies": {"lodash": "^4.17.21", "legacy-thing": "^1.0.0"}},
    "node_modules/lodash": {"version": "4.17.21"},
    "node_modules/legacy-thing": {"version": "1.0.0", "dependencies": {"lodash": "3.10.1"}},
    "node_modules/legacy-thing/node_modules/lodash": {"version": "3.10.1"}
  }
}`

	tests := []struct {
		name  string
		files map[string]string
		pkg   *extractor.Package
		want  bool
	}{
		{
			name:  "the version the declaration resolved to is direct",
			files: map[string]string{"package.json": manifest, "package-lock.json": lockfile},
			pkg:   &extractor.Package{Name: "lodash", Version: "4.17.21", PURLType: "npm"},
			want:  true,
		},
		{
			name:  "a nested copy of the same name is not direct",
			files: map[string]string{"package.json": manifest, "package-lock.json": lockfile},
			pkg:   &extractor.Package{Name: "lodash", Version: "3.10.1", PURLType: "npm"},
			want:  false,
		},
		{
			name:  "the dependency that pulled the nested copy is still direct",
			files: map[string]string{"package.json": manifest, "package-lock.json": lockfile},
			pkg:   &extractor.Package{Name: "legacy-thing", Version: "1.0.0", PURLType: "npm"},
			want:  true,
		},
		{
			name:  "without a lockfile every copy of a declared name stays direct",
			files: map[string]string{"package.json": manifest},
			pkg:   &extractor.Package{Name: "lodash", Version: "3.10.1", PURLType: "npm"},
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ws := workspace.NewMemory()
			t.Cleanup(func() { _ = ws.Close() })
			for name, contents := range tt.files {
				if err := ws.WriteFile(name, []byte(contents), 0o644); err != nil {
					t.Fatalf("write %s: %v", name, err)
				}
			}
			direct := compare.CollectDirectDependenciesFromWorkspace(ws)
			if got := ExtractorPackageIsDirect(tt.pkg, direct); got != tt.want {
				t.Errorf("ExtractorPackageIsDirect(%s@%s) = %v, want %v (collected %v)",
					tt.pkg.Name, tt.pkg.Version, got, tt.want, direct)
			}
		})
	}
}

func TestExtractorPackageToProto_DirectDetection(t *testing.T) {
	tests := []struct {
		name       string
		pkg        *extractor.Package
		direct     map[string]bool
		wantDirect bool
	}{
		{
			name: "Go direct dependency",
			pkg: &extractor.Package{
				Name:     "github.com/stretchr/testify",
				Version:  "1.8.0",
				PURLType: "golang",
			},
			direct: map[string]bool{
				"github.com/stretchr/testify": true,
			},
			wantDirect: true,
		},
		{
			name: "Go indirect dependency",
			pkg: &extractor.Package{
				Name:     "github.com/davecgh/go-spew",
				Version:  "1.1.1",
				PURLType: "golang",
			},
			direct: map[string]bool{
				"github.com/stretchr/testify": true,
				"github.com/davecgh/go-spew":  false,
			},
			wantDirect: false,
		},
		{
			name: "npm direct dependency",
			pkg: &extractor.Package{
				Name:     "react",
				Version:  "18.2.0",
				PURLType: "npm",
			},
			direct: map[string]bool{
				"react": true,
			},
			wantDirect: true,
		},
		{
			name: "npm scoped package direct",
			pkg: &extractor.Package{
				Name:     "@types/node",
				Version:  "20.0.0",
				PURLType: "npm",
			},
			direct: map[string]bool{
				"@types/node": true,
			},
			wantDirect: true,
		},
		{
			name: "npm transitive dependency",
			pkg: &extractor.Package{
				Name:     "loose-envify",
				Version:  "1.4.0",
				PURLType: "npm",
			},
			direct: map[string]bool{
				"react": true,
			},
			wantDirect: false,
		},
		{
			name: "cargo direct dependency",
			pkg: &extractor.Package{
				Name:     "tokio",
				Version:  "1.28.0",
				PURLType: "cargo",
			},
			direct: map[string]bool{
				"tokio": true,
			},
			wantDirect: true,
		},
		{
			name: "cargo transitive dependency",
			pkg: &extractor.Package{
				Name:     "mio",
				Version:  "0.8.6",
				PURLType: "cargo",
			},
			direct: map[string]bool{
				"tokio": true,
			},
			wantDirect: false,
		},
		{
			name: "pypi direct dependency",
			pkg: &extractor.Package{
				Name:     "flask",
				Version:  "2.0.0",
				PURLType: "pypi",
			},
			direct: map[string]bool{
				"flask": true,
			},
			wantDirect: true,
		},
		{
			name: "pypi normalized name match",
			pkg: &extractor.Package{
				Name:     "Flask-SQLAlchemy",
				Version:  "3.0.0",
				PURLType: "pypi",
			},
			direct: map[string]bool{
				"flask-sqlalchemy": true,
			},
			wantDirect: true,
		},
		{
			name: "cargo hyphenated crate matches the folded key",
			pkg: &extractor.Package{
				Name:     "serde-json",
				Version:  "1.0.117",
				PURLType: "cargo",
			},
			direct: map[string]bool{
				"serde_json": true,
			},
			wantDirect: true,
		},
		{
			name: "pypi transitive dependency",
			pkg: &extractor.Package{
				Name:     "werkzeug",
				Version:  "2.2.0",
				PURLType: "pypi",
			},
			direct: map[string]bool{
				"flask": true,
			},
			wantDirect: false,
		},
		{
			name: "nil direct map",
			pkg: &extractor.Package{
				Name:     "react",
				Version:  "18.2.0",
				PURLType: "npm",
			},
			direct:     nil,
			wantDirect: false,
		},
		{
			name: "mise tool direct without direct map",
			pkg: &extractor.Package{
				Name:     "node",
				Version:  "20.11.0",
				PURLType: purlx.TypeMise,
			},
			direct:     nil,
			wantDirect: true,
		},
		{
			name: "asdf tool direct without direct map",
			pkg: &extractor.Package{
				Name:     "golang",
				Version:  "1.26.2",
				PURLType: purlx.TypeAsdf,
			},
			direct:     nil,
			wantDirect: true,
		},
		{
			name:       "nil package",
			pkg:        nil,
			direct:     map[string]bool{"react": true},
			wantDirect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractorPackageToProto(tt.pkg, tt.direct)
			if tt.pkg == nil {
				if result != nil {
					t.Error("expected nil result for nil package")
				}
				return
			}
			if result.Direct != tt.wantDirect {
				t.Errorf("Direct = %v, want %v", result.Direct, tt.wantDirect)
			}
		})
	}
}

func TestExtractorPackageToProto_CustomEcosystems(t *testing.T) {
	tests := []struct {
		name    string
		pkg     *extractor.Package
		wantEco string
	}{
		{
			name:    "mise",
			pkg:     &extractor.Package{Name: "node", Version: "20.11.0", PURLType: purlx.TypeMise},
			wantEco: "mise",
		},
		{
			name:    "asdf",
			pkg:     &extractor.Package{Name: "golang", Version: "1.26.2", PURLType: purlx.TypeAsdf},
			wantEco: "asdf",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractorPackageToProto(tt.pkg, nil)
			if got.Ecosystem != tt.wantEco {
				t.Errorf("Ecosystem = %q, want %q", got.Ecosystem, tt.wantEco)
			}
		})
	}
}

func TestExtractorPackagesToProto(t *testing.T) {
	t.Run("empty slice", func(t *testing.T) {
		result := ExtractorPackagesToProto(nil, nil)
		if result != nil {
			t.Error("expected nil for empty slice")
		}
	})

	t.Run("mixed ecosystems", func(t *testing.T) {
		pkgs := []*extractor.Package{
			{Name: "github.com/stretchr/testify", Version: "1.8.0", PURLType: "golang"},
			{Name: "react", Version: "18.2.0", PURLType: "npm"},
			{Name: "tokio", Version: "1.28.0", PURLType: "cargo"},
		}
		direct := map[string]bool{
			"github.com/stretchr/testify": true,
			"react":                       true,
			"tokio":                       true,
		}

		result := ExtractorPackagesToProto(pkgs, direct)
		if len(result) != 3 {
			t.Errorf("expected 3 packages, got %d", len(result))
		}

		// All should be marked as direct
		for i, pkg := range result {
			if !pkg.Direct {
				t.Errorf("package %d (%s) should be direct", i, pkg.Name)
			}
		}
	})
}

func TestExtractorPackagesFromProto(t *testing.T) {
	t.Run("empty slice", func(t *testing.T) {
		pkgs, direct := ExtractorPackagesFromProto(nil)
		if pkgs != nil || direct != nil {
			t.Error("expected nil for empty slice")
		}
	})

	t.Run("preserves go submodule directness for reconversion", func(t *testing.T) {
		protoPkgs := []*dependencyv1.Package{
			{
				Name:    "github.com/bytedance/sonic",
				Version: "v1.14.2",
				Purl:    "pkg:golang/github.com/bytedance/sonic@v1.14.2",
				Direct:  true,
			},
			{
				Name:    "github.com/bytedance/sonic/loader",
				Version: "v0.4.0",
				Purl:    "pkg:golang/github.com/bytedance/sonic/loader@v0.4.0",
				Direct:  false,
			},
		}

		pkgs, direct := ExtractorPackagesFromProto(protoPkgs)
		if len(pkgs) != 2 {
			t.Fatalf("expected 2 packages, got %d", len(pkgs))
		}
		if pkgs[0].PURLType != "golang" || pkgs[1].PURLType != "golang" {
			t.Fatalf("expected reconstructed golang PURL types, got %q and %q", pkgs[0].PURLType, pkgs[1].PURLType)
		}
		if !direct["github.com/bytedance/sonic"] {
			t.Fatal("expected parent module to be direct")
		}
		if got, ok := direct["github.com/bytedance/sonic/loader"]; !ok || got {
			t.Fatalf("expected nested module to be recorded as indirect, got value=%v present=%v", got, ok)
		}

		roundTripped := ExtractorPackagesToProto(pkgs, direct)
		if !roundTripped[0].Direct {
			t.Fatal("expected parent module to remain direct after reconversion")
		}
		if roundTripped[1].Direct {
			t.Fatal("expected nested module to remain indirect after reconversion")
		}
	})

	// The map this returns is fed straight back to ExtractorPackageIsDirect, so
	// it has to be keyed the way that lookup keys. A crate published with a
	// hyphen is the case that catches a recorder keyed by identity instead of
	// by equivalence: the lookup would ask for the folded spelling and find
	// nothing, silently demoting a direct dependency to transitive.
	t.Run("preserves directness for names their ecosystem folds", func(t *testing.T) {
		protoPkgs := []*dependencyv1.Package{
			{Name: "async-trait", Version: "0.1.80", Purl: "pkg:cargo/async-trait@0.1.80", Direct: true},
			{Name: "zope.interface", Version: "6.4", Purl: "pkg:pypi/zope.interface@6.4", Direct: true},
		}

		pkgs, direct := ExtractorPackagesFromProto(protoPkgs)
		roundTripped := ExtractorPackagesToProto(pkgs, direct)
		for i, pkg := range roundTripped {
			if !pkg.Direct {
				t.Errorf("package %d (%s) lost its directness in the round trip", i, pkg.Name)
			}
		}
		if got := roundTripped[0].Name; got != "async-trait" {
			t.Errorf("crate round-tripped as %q, want its published spelling", got)
		}
	})
}

func TestEcosystemFromPURLType(t *testing.T) {
	tests := []struct {
		purlType string
		want     string
	}{
		{"githubactions", "GitHub Actions"},
		{"npm", ""},
		{"golang", ""},
		{"unknown", ""},
	}

	for _, tt := range tests {
		t.Run(tt.purlType, func(t *testing.T) {
			got := ecosystemFromPURLType(tt.purlType)
			if got != tt.want {
				t.Errorf("ecosystemFromPURLType(%q) = %q, want %q", tt.purlType, got, tt.want)
			}
		})
	}
}

// TestProtoRoundTripPreservesNpmVersionDirectness drives the classification
// through the proto round trip and asserts it against the direct path, because
// the answer has to be the same on both. The CLI in local mode classifies in
// process, while the server and the MCP surface decode a ScanResponse and
// reconstruct the direct set from it, so a distinction that survives one path and
// not the other is worse than a uniform wrong answer: which surface a caller came
// through is not something a policy author can reason about.
func TestProtoRoundTripPreservesNpmVersionDirectness(t *testing.T) {
	const manifest = `{"name":"app","dependencies":{"lodash":"^4.17.21","legacy-thing":"^1.0.0"}}`
	const lockfile = `{
  "name": "app",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "app", "dependencies": {"lodash": "^4.17.21", "legacy-thing": "^1.0.0"}},
    "node_modules/lodash": {"version": "4.17.21"},
    "node_modules/legacy-thing": {"version": "1.0.0", "dependencies": {"lodash": "3.10.1"}},
    "node_modules/legacy-thing/node_modules/lodash": {"version": "3.10.1"}
  }
}`

	ws := workspace.NewMemory()
	t.Cleanup(func() { _ = ws.Close() })
	for name, contents := range map[string]string{"package.json": manifest, "package-lock.json": lockfile} {
		if err := ws.WriteFile(name, []byte(contents), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	direct := compare.CollectDirectDependenciesFromWorkspace(ws)

	scanned := []*extractor.Package{
		{Name: "lodash", Version: "4.17.21", PURLType: "npm"},
		{Name: "lodash", Version: "3.10.1", PURLType: "npm"},
		{Name: "legacy-thing", Version: "1.0.0", PURLType: "npm"},
	}
	want := map[string]bool{
		"lodash@4.17.21":     true,
		"lodash@3.10.1":      false,
		"legacy-thing@1.0.0": true,
	}

	// The direct path is the reference answer, and is asserted rather than
	// assumed so a regression there cannot make the round trip look correct.
	protos := ExtractorPackagesToProto(scanned, direct)
	for _, p := range protos {
		key := p.GetName() + "@" + p.GetVersion()
		if got := p.GetDirect(); got != want[key] {
			t.Fatalf("direct path: %s direct=%v, want %v", key, got, want[key])
		}
	}

	// Reconstructing from the protos and re-running the lookup has to reach the
	// same answer, since that is what a decoded ScanResponse does.
	rebuilt, rebuiltDirect := ExtractorPackagesFromProto(protos)
	for _, p := range rebuilt {
		key := p.Name + "@" + p.Version
		if got := ExtractorPackageIsDirect(p, rebuiltDirect); got != want[key] {
			t.Errorf("after proto round trip: %s direct=%v, want %v (rebuilt map %v)",
				key, got, want[key], rebuiltDirect)
		}
	}
}

// TestProtoRoundTripKeepsUnresolvedNamesDirect pins the under-claiming guard
// across the round trip. A project with no committed lockfile has no resolution,
// so every copy of a declared name is direct; rebuilding the set from protos must
// not turn the absence of a version marker into an absence of directness.
func TestProtoRoundTripKeepsUnresolvedNamesDirect(t *testing.T) {
	scanned := []*extractor.Package{
		{Name: "lodash", Version: "4.17.21", PURLType: "npm"},
		{Name: "lodash", Version: "3.10.1", PURLType: "npm"},
	}
	// Both copies are direct on the way in, which is what a name-only
	// classification produces for an unlocked project.
	direct := map[string]bool{"lodash": true}

	protos := ExtractorPackagesToProto(scanned, direct)
	rebuilt, rebuiltDirect := ExtractorPackagesFromProto(protos)
	for _, p := range rebuilt {
		if !ExtractorPackageIsDirect(p, rebuiltDirect) {
			t.Errorf("%s@%s lost its directness through the round trip (rebuilt map %v)",
				p.Name, p.Version, rebuiltDirect)
		}
	}
}

// TestNpmWorkspaceDuplicateVersionsClassifySeparately drives the workspace case
// through the real collector, which is where the interaction lives: the manifest
// walk visits every member's package.json and contributes a bare name, so without
// a version marker from the lockfile the lookup falls back to that name and marks
// both copies direct. The member manifests are written deliberately for that
// reason.
func TestNpmWorkspaceDuplicateVersionsClassifySeparately(t *testing.T) {
	files := map[string]string{
		"package.json":              `{"name":"monorepo","workspaces":["packages/*"]}`,
		"packages/api/package.json": `{"name":"@acme/api","version":"1.0.0","dependencies":{"lodash":"^4.17.21"}}`,
		"packages/web/package.json": `{"name":"@acme/web","version":"1.0.0","dependencies":{"legacy-thing":"^1.0.0"}}`,
		"package-lock.json": `{
  "name": "monorepo",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "monorepo", "workspaces": ["packages/*"]},
    "packages/api": {"name": "@acme/api", "version": "1.0.0", "dependencies": {"lodash": "^4.17.21"}},
    "packages/web": {"name": "@acme/web", "version": "1.0.0", "dependencies": {"legacy-thing": "^1.0.0"}},
    "node_modules/@acme/api": {"resolved": "packages/api", "link": true},
    "node_modules/@acme/web": {"resolved": "packages/web", "link": true},
    "node_modules/lodash": {"version": "4.17.21"},
    "node_modules/legacy-thing": {"version": "1.0.0", "dependencies": {"lodash": "3.10.1"}},
    "packages/web/node_modules/lodash": {"version": "3.10.1"}
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
	direct := compare.CollectDirectDependenciesFromWorkspace(ws)

	tests := []struct {
		name string
		pkg  *extractor.Package
		want bool
	}{
		{
			name: "the version a member declares is direct",
			pkg:  &extractor.Package{Name: "lodash", Version: "4.17.21", PURLType: "npm"},
			want: true,
		},
		{
			name: "the copy nested in another member is not direct",
			pkg:  &extractor.Package{Name: "lodash", Version: "3.10.1", PURLType: "npm"},
			want: false,
		},
		{
			name: "the other member's own declaration is direct",
			pkg:  &extractor.Package{Name: "legacy-thing", Version: "1.0.0", PURLType: "npm"},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ExtractorPackageIsDirect(tt.pkg, direct); got != tt.want {
				t.Errorf("ExtractorPackageIsDirect(%s@%s) = %v, want %v (collected %v)",
					tt.pkg.Name, tt.pkg.Version, got, tt.want, direct)
			}
		})
	}
}
