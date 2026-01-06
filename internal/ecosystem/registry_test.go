package ecosystem

import (
	"testing"
)

func TestRegistry(t *testing.T) {
	reg := NewRegistry()

	t.Run("lookup by ecosystem", func(t *testing.T) {
		r := reg.Lookup("go")
		if r == nil {
			t.Fatal("expected to find Go ecosystem")
		}
		if r.Ecosystem != Go {
			t.Errorf("expected Go, got %s", r.Ecosystem)
		}
	})

	t.Run("lookup by alias", func(t *testing.T) {
		r := reg.Lookup("golang")
		if r == nil {
			t.Fatal("expected to find Go ecosystem via alias")
		}
		if r.Ecosystem != Go {
			t.Errorf("expected Go, got %s", r.Ecosystem)
		}
	})

	t.Run("get by ecosystem", func(t *testing.T) {
		r := reg.Get(Go)
		if r == nil {
			t.Fatal("expected to find Go ecosystem")
		}
		if r.DisplayName != "Go" {
			t.Errorf("expected DisplayName 'Go', got %s", r.DisplayName)
		}
	})

	t.Run("capabilities", func(t *testing.T) {
		r := reg.Lookup("go")
		if r == nil {
			t.Fatal("expected to find Go ecosystem")
		}

		if !r.HasCapability(CapInventory) {
			t.Error("expected Go to have inventory capability")
		}
		if !r.HasCapability(CapGraph) {
			t.Error("expected Go to have graph capability")
		}
		if !r.HasCapability(CapProxy) {
			t.Error("expected Go to have proxy capability")
		}
		if !r.HasCapability(CapLicense) {
			t.Error("expected Go to have license capability")
		}
		if !r.HasCapability(CapFix) {
			t.Error("expected Go to have fix capability")
		}
		if !r.HasCapability(CapSBOM) {
			t.Error("expected Go to have SBOM capability")
		}
	})

	t.Run("with capability filter", func(t *testing.T) {
		graphEcos := reg.WithCapability(CapGraph)
		if len(graphEcos) == 0 {
			t.Error("expected at least one ecosystem with graph support")
		}

		found := false
		for _, e := range graphEcos {
			if e.Ecosystem == Go {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected Go to be in graph-capable ecosystems")
		}
	})

	t.Run("all ecosystems sorted", func(t *testing.T) {
		all := reg.All()
		if len(all) == 0 {
			t.Fatal("expected registered ecosystems")
		}

		// Verify sorting by display name
		for i := 1; i < len(all); i++ {
			if all[i-1].DisplayName > all[i].DisplayName {
				t.Errorf("ecosystems not sorted: %s > %s", all[i-1].DisplayName, all[i].DisplayName)
			}
		}
	})

	t.Run("registration metadata", func(t *testing.T) {
		r := reg.Get(NPM)
		if r == nil {
			t.Fatal("expected to find npm ecosystem")
		}

		if r.DisplayName != "npm" {
			t.Errorf("expected DisplayName 'npm', got %s", r.DisplayName)
		}
		if r.Description == "" {
			t.Error("expected non-empty description")
		}
		if len(r.Lockfiles) == 0 {
			t.Error("expected lockfile patterns")
		}
		if r.UpstreamURL == "" {
			t.Error("expected upstream URL")
		}
		if r.OSVName == "" {
			t.Error("expected OSV name")
		}
	})

	t.Run("capability list", func(t *testing.T) {
		r := reg.Get(Go)
		if r == nil {
			t.Fatal("expected to find Go ecosystem")
		}

		caps := r.CapabilityList()
		if len(caps) == 0 {
			t.Error("expected Go to have capabilities")
		}

		// Go should have all capabilities
		expected := map[Capability]bool{
			CapInventory: true,
			CapGraph:     true,
			CapProxy:     true,
			CapLicense:   true,
			CapFix:       true,
			CapSBOM:      true,
		}
		for _, c := range caps {
			delete(expected, c)
		}
		if len(expected) > 0 {
			t.Errorf("missing capabilities: %v", expected)
		}
	})
}

func TestHasGraphSupport(t *testing.T) {
	tests := []struct {
		eco      Ecosystem
		expected bool
	}{
		{Go, true},
		{NPM, true},
		{PyPI, true},
		{Cargo, true},
		{RubyGems, true},
		{Maven, true},
		{NuGet, true},
		{Hex, true},
		{Pub, true},
		{CocoaPods, false},
		{Packagist, false},
		{Unknown, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.eco), func(t *testing.T) {
			got := HasGraphSupport(tt.eco)
			if got != tt.expected {
				t.Errorf("HasGraphSupport(%s) = %v, want %v", tt.eco, got, tt.expected)
			}
		})
	}
}

func TestHasProxySupportFor(t *testing.T) {
	tests := []struct {
		eco      Ecosystem
		expected bool
	}{
		{Go, true},
		{NPM, true},
		{PyPI, true},
		{RubyGems, true},
		{Cargo, false},
		{Maven, false},
		{Unknown, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.eco), func(t *testing.T) {
			got := HasProxySupportFor(tt.eco)
			if got != tt.expected {
				t.Errorf("HasProxySupportFor(%s) = %v, want %v", tt.eco, got, tt.expected)
			}
		})
	}
}

func TestHasLicenseSupport(t *testing.T) {
	tests := []struct {
		eco      Ecosystem
		expected bool
	}{
		{Go, true},
		{NPM, true},
		{Cargo, true},
		{PyPI, false},
		{Maven, false},
		{Unknown, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.eco), func(t *testing.T) {
			got := HasLicenseSupport(tt.eco)
			if got != tt.expected {
				t.Errorf("HasLicenseSupport(%s) = %v, want %v", tt.eco, got, tt.expected)
			}
		})
	}
}

func TestGraphSupportedEcosystems(t *testing.T) {
	ecos := GraphSupportedEcosystems()
	if len(ecos) == 0 {
		t.Error("expected at least one graph-supported ecosystem")
	}

	// Go should be in the list
	found := false
	for _, e := range ecos {
		if e == Go {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected Go to be in graph-supported ecosystems")
	}
}

// Note: TestWithProxy in ecosystem_test.go tests the WithProxy() wrapper.
// ProxySupportedEcosystems is tested indirectly via TestHasProxySupportFor.

func TestCapabilityBitmask(t *testing.T) {
	// Test that capabilities can be combined
	caps := CapInventory | CapGraph | CapProxy

	if caps&CapInventory == 0 {
		t.Error("expected CapInventory to be set")
	}
	if caps&CapGraph == 0 {
		t.Error("expected CapGraph to be set")
	}
	if caps&CapProxy == 0 {
		t.Error("expected CapProxy to be set")
	}
	if caps&CapLicense != 0 {
		t.Error("expected CapLicense to NOT be set")
	}
}

func TestCapabilityString(t *testing.T) {
	tests := []struct {
		cap  Capability
		want string
	}{
		{CapInventory, "Inventory"},
		{CapGraph, "Graph"},
		{CapProxy, "Proxy"},
		{CapLicense, "License"},
		{CapFix, "Fix"},
		{CapSBOM, "SBOM"},
		{Capability(128), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.cap.String(); got != tt.want {
				t.Errorf("Capability.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAllCapabilities(t *testing.T) {
	caps := AllCapabilities()
	if len(caps) != 6 {
		t.Errorf("AllCapabilities() returned %d, want 6", len(caps))
	}
}

func TestRegistryAllScalibrPrefixes(t *testing.T) {
	reg := NewRegistry()
	prefixes := reg.AllScalibrPrefixes()

	if len(prefixes) == 0 {
		t.Fatal("expected SCALIBR prefixes")
	}

	// Check for core prefixes
	expected := map[string]bool{
		"go":         true,
		"javascript": true,
		"python":     true,
		"ruby":       true,
		"rust":       true,
		"java":       true,
		"dotnet":     true,
		"github":     true, // extra
		"os":         true, // extra
	}

	seen := make(map[string]bool)
	for _, p := range prefixes {
		seen[p] = true
	}

	for exp := range expected {
		if !seen[exp] {
			t.Errorf("missing expected prefix: %s", exp)
		}
	}
}

func TestRegistryEcosystems(t *testing.T) {
	reg := NewRegistry()
	ecos := reg.Ecosystems()

	if len(ecos) == 0 {
		t.Fatal("expected ecosystems")
	}

	// Verify sorted
	for i := 1; i < len(ecos); i++ {
		if string(ecos[i-1]) > string(ecos[i]) {
			t.Errorf("ecosystems not sorted: %s > %s", ecos[i-1], ecos[i])
		}
	}
}
