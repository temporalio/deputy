package proto

import (
	"testing"

	"github.com/google/osv-scalibr/extractor"

	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	"github.com/temporalio/deputy/internal/purlx"
)

func TestNormalizePyPIName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"flask", "flask"},
		{"Flask", "flask"},
		{"FLASK", "flask"},
		{"flask-restful", "flask_restful"},
		{"Flask-RESTful", "flask_restful"},
		{"google-cloud-storage", "google_cloud_storage"},
		{"zope.interface", "zope_interface"},
		{"Zope.Interface", "zope_interface"},
		{"Flask_RESTful", "flask_restful"},
		{"some.package-name", "some_package_name"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizePyPIName(tt.input)
			if got != tt.want {
				t.Errorf("normalizePyPIName(%q) = %q, want %q", tt.input, got, tt.want)
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
				"flask_sqlalchemy": true,
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
