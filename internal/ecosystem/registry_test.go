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
		{CocoaPods, false},
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
