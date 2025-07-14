package main

import (
	"strings"
	"testing"

	"github.com/google/osv-scalibr/extractor"
)

func TestExtractCanonicalPackageName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"modernc.org/cc/v3", "modernc.org/cc"},
		{"modernc.org/cc/v4", "modernc.org/cc"},
		{"modernc.org/cc", "modernc.org/cc"},
		{"github.com/example/pkg/v2", "github.com/example/pkg"},
		{"github.com/example/pkg", "github.com/example/pkg"},
		{"github.com/example/pkg/v10", "github.com/example/pkg"},
		{"github.com/example/pkg/v1", "github.com/example/pkg/v1"}, // v1 doesn't get stripped
		{"github.com/example/pkg/v0", "github.com/example/pkg/v0"}, // v0 doesn't get stripped
		{"github.com/example/something", "github.com/example/something"},
		
		// gopkg.in URL tests
		{"gopkg.in/go-jose/go-jose.v2", "github.com/go-jose/go-jose"},
		{"gopkg.in/go-jose/go-jose.v3", "github.com/go-jose/go-jose"},
		{"gopkg.in/yaml.v2", "github.com/go-yaml/yaml"},
		{"gopkg.in/yaml.v3", "github.com/go-yaml/yaml"},
		{"gopkg.in/check.v1", "github.com/go-check/check"},
		{"gopkg.in/user/repo.v4", "github.com/user/repo"},
		{"gopkg.in/user/repo/subpkg.v2", "github.com/user/repo/subpkg"},
		
		// Edge cases
		{"gopkg.in/invalid", "gopkg.in/invalid"}, // No version suffix
		{"gopkg.in/", "gopkg.in/"},               // Empty after prefix
		{"github.com/go-jose/go-jose/v4", "github.com/go-jose/go-jose"}, // Regular GitHub URL with version
	}

	for _, test := range tests {
		result := extractCanonicalPackageName(test.input)
		if result != test.expected {
			t.Errorf("extractCanonicalPackageName(%q) = %q, expected %q",
				test.input, result, test.expected)
		}
	}
}

func TestNormalizeGopkgInURL(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		// gopkg.in URLs that should be normalized
		{"gopkg.in/go-jose/go-jose.v2", "github.com/go-jose/go-jose"},
		{"gopkg.in/go-jose/go-jose.v3", "github.com/go-jose/go-jose"},
		{"gopkg.in/yaml.v2", "github.com/go-yaml/yaml"},
		{"gopkg.in/yaml.v3", "github.com/go-yaml/yaml"},
		{"gopkg.in/check.v1", "github.com/go-check/check"},
		{"gopkg.in/user/repo.v4", "github.com/user/repo"},
		{"gopkg.in/user/repo/subpkg.v2", "github.com/user/repo/subpkg"},
		
		// URLs that should not be changed
		{"github.com/go-jose/go-jose/v4", "github.com/go-jose/go-jose/v4"},
		{"modernc.org/cc/v3", "modernc.org/cc/v3"},
		{"example.com/pkg", "example.com/pkg"},
		
		// Edge cases
		{"gopkg.in/invalid", "gopkg.in/invalid"}, // No version suffix
		{"gopkg.in/", "gopkg.in/"},               // Empty after prefix
		{"", ""},                                 // Empty string
	}

	for _, test := range tests {
		result := normalizeGopkgInURL(test.input)
		if result != test.expected {
			t.Errorf("normalizeGopkgInURL(%q) = %q, expected %q",
				test.input, result, test.expected)
		}
	}
}

func TestParseGoPackage(t *testing.T) {
	tests := []struct {
		name              string
		version           string
		expectedCanonical string
		expectedMajor     int
	}{
		{"modernc.org/cc/v3", "3.41.0", "modernc.org/cc", 3},
		{"modernc.org/cc/v4", "4.24.4", "modernc.org/cc", 4},
		{"modernc.org/cc", "1.0.0", "modernc.org/cc", 1},
		{"github.com/example/pkg/v2", "2.1.0", "github.com/example/pkg", 2},
		
		// gopkg.in URL tests
		{"gopkg.in/go-jose/go-jose.v2", "2.6.3", "github.com/go-jose/go-jose", 2},
		{"gopkg.in/go-jose/go-jose.v3", "3.0.0", "github.com/go-jose/go-jose", 3},
		{"gopkg.in/yaml.v2", "2.4.0", "github.com/go-yaml/yaml", 2},
		{"gopkg.in/yaml.v3", "3.0.1", "github.com/go-yaml/yaml", 3},
		{"gopkg.in/check.v1", "1.0.0", "github.com/go-check/check", 1},
	}

	for _, test := range tests {
		// Use extractor.Package directly
		pkg := &extractor.Package{
			Name:    test.name,
			Version: test.version,
		}
		info := parseGoPackage(pkg)

		if info.OriginalName != test.name {
			t.Errorf("parseGoPackage(%q).OriginalName = %q, expected %q",
				test.name, info.OriginalName, test.name)
		}

		if info.CanonicalName != test.expectedCanonical {
			t.Errorf("parseGoPackage(%q).CanonicalName = %q, expected %q",
				test.name, info.CanonicalName, test.expectedCanonical)
		}

		if info.MajorVersion != test.expectedMajor {
			t.Errorf("parseGoPackage(%q).MajorVersion = %d, expected %d",
				test.name, info.MajorVersion, test.expectedMajor)
		}
	}
}

func TestCompareGoPackageChanges(t *testing.T) {
	tests := []struct {
		oldPkg   GoPackageInfo
		newPkg   GoPackageInfo
		expected int
		desc     string
	}{
		{
			GoPackageInfo{OriginalName: "modernc.org/cc/v3", FullName: "modernc.org/cc/v3", Version: "3.41.0", MajorVersion: 3},
			GoPackageInfo{OriginalName: "modernc.org/cc/v4", FullName: "modernc.org/cc/v4", Version: "4.24.4", MajorVersion: 4},
			1, // Upgrade
			"Major version upgrade v3->v4",
		},
		{
			GoPackageInfo{OriginalName: "modernc.org/cc/v4", FullName: "modernc.org/cc/v4", Version: "4.24.4", MajorVersion: 4},
			GoPackageInfo{OriginalName: "modernc.org/cc/v3", FullName: "modernc.org/cc/v3", Version: "3.41.0", MajorVersion: 3},
			-1, // Downgrade
			"Major version downgrade v4->v3",
		},
		{
			GoPackageInfo{OriginalName: "modernc.org/cc/v3", FullName: "modernc.org/cc/v3", Version: "3.41.0", MajorVersion: 3},
			GoPackageInfo{OriginalName: "modernc.org/cc/v3", FullName: "modernc.org/cc/v3", Version: "3.42.0", MajorVersion: 3},
			1, // Upgrade (same major, higher minor)
			"Minor version upgrade within same major",
		},
	}

	for _, test := range tests {
		result := compareGoPackageChanges(test.oldPkg, test.newPkg)
		if result != test.expected {
			t.Errorf("%s: compareGoPackageChanges() = %d, expected %d",
				test.desc, result, test.expected)
		}
	}
}

func TestGoModuleVersioning(t *testing.T) {
	// Example showing how modernc.org/cc/v3 -> modernc.org/cc/v4 is detected as an upgrade
	oldPkg := &extractor.Package{Name: "modernc.org/cc/v3", Version: "3.41.0"}
	newPkg := &extractor.Package{Name: "modernc.org/cc/v4", Version: "4.24.4"}

	oldInfo := parseGoPackage(oldPkg)
	newInfo := parseGoPackage(newPkg)

	t.Logf("Old: %s -> %s (canonical: %s, major: %d)",
		oldInfo.OriginalName, oldInfo.FullName, oldInfo.CanonicalName, oldInfo.MajorVersion)
	t.Logf("New: %s -> %s (canonical: %s, major: %d)",
		newInfo.OriginalName, newInfo.FullName, newInfo.CanonicalName, newInfo.MajorVersion)

	result := compareGoPackageChanges(oldInfo, newInfo)
	if result == 1 {
		t.Logf("Result: Major version upgrade detected!")
	}

	// Test with comparePackages function
	changes := comparePackages([]*extractor.Package{oldPkg}, []*extractor.Package{newPkg})
	if len(changes) == 1 && changes[0].ChangeType == Updated {
		t.Logf("✓ comparePackages correctly detected upgrade from %s to %s",
			changes[0].OldName, changes[0].Name)
	}
}

func TestGopkgInVanityURLScenario(t *testing.T) {
	// Test the exact scenario described: gopkg.in/go-jose/go-jose.v2 -> github.com/go-jose/go-jose/v4
	oldPkg := &extractor.Package{Name: "gopkg.in/go-jose/go-jose.v2", Version: "2.6.3"}
	newPkg := &extractor.Package{Name: "github.com/go-jose/go-jose/v4", Version: "4.0.5"}

	oldInfo := parseGoPackage(oldPkg)
	newInfo := parseGoPackage(newPkg)

	t.Logf("Old: %s -> %s (canonical: %s, major: %d)",
		oldInfo.OriginalName, oldInfo.FullName, oldInfo.CanonicalName, oldInfo.MajorVersion)
	t.Logf("New: %s -> %s (canonical: %s, major: %d)",
		newInfo.OriginalName, newInfo.FullName, newInfo.CanonicalName, newInfo.MajorVersion)

	// Both should have the same canonical name
	if oldInfo.CanonicalName != newInfo.CanonicalName {
		t.Errorf("Expected same canonical name, got old=%q, new=%q",
			oldInfo.CanonicalName, newInfo.CanonicalName)
	}

	expectedCanonical := "github.com/go-jose/go-jose"
	if oldInfo.CanonicalName != expectedCanonical {
		t.Errorf("Expected canonical name %q, got %q", expectedCanonical, oldInfo.CanonicalName)
	}

	// Major versions should be parsed correctly
	if oldInfo.MajorVersion != 2 {
		t.Errorf("Expected old major version 2, got %d", oldInfo.MajorVersion)
	}
	if newInfo.MajorVersion != 4 {
		t.Errorf("Expected new major version 4, got %d", newInfo.MajorVersion)
	}

	// Test with comparePackages function
	changes := comparePackages([]*extractor.Package{oldPkg}, []*extractor.Package{newPkg})
	if len(changes) != 1 {
		t.Fatalf("Expected 1 change, got %d", len(changes))
	}

	change := changes[0]
	if change.ChangeType != Updated {
		t.Errorf("Expected Updated change type, got %v", change.ChangeType)
	}

	t.Logf("✓ Successfully detected gopkg.in vanity URL upgrade:")
	t.Logf("  From: %s (%s)", change.OldName, change.BaseVersion)
	t.Logf("  To:   %s (%s)", change.Name, change.TargetVersion)

	// Verify the change shows the normalized names
	if !strings.Contains(change.Name, "github.com/go-jose/go-jose") {
		t.Errorf("Expected new name to contain github.com/go-jose/go-jose, got %q", change.Name)
	}
}
