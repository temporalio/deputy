package inventory

import (
	"testing"

	"github.com/google/osv-scalibr/plugin"
	pl "github.com/google/osv-scalibr/plugin/list"

	ghactions "github.com/picatz/deputy/internal/inventory/plugins/github/actionsx"
)

func TestFilterInventoryPluginsIncludesGoPlugin(t *testing.T) {
	plugins, err := pl.FromNames([]string{"go/gomod"})
	if err != nil {
		t.Fatalf("pl.FromNames: %v", err)
	}
	filtered := filterInventoryPlugins(plugins)
	if len(filtered) == 0 {
		t.Fatalf("go/gomod plugin should pass filter")
	}
	if filtered[0].Name() != "go/gomod" {
		t.Fatalf("expected go/gomod plugin, got %s", filtered[0].Name())
	}
}

func TestFilterInventoryPluginsIncludesGitHubActionsPlugin(t *testing.T) {
	// The GitHub Actions plugin is a Deputy-provided plugin (not from SCALIBR)
	// that uses the "github/actions" name. The "github" prefix must be in the
	// allowed prefixes list for it to pass through filterInventoryPlugins.
	plugins := []plugin.Plugin{ghactions.New()}
	filtered := filterInventoryPlugins(plugins)
	if len(filtered) == 0 {
		t.Fatalf("github/actions plugin should pass filter, got empty result")
	}
	if filtered[0].Name() != ghactions.Name {
		t.Fatalf("expected %s plugin, got %s", ghactions.Name, filtered[0].Name())
	}
}

func TestFilterInventoryPluginsMixedPlugins(t *testing.T) {
	// Test that both SCALIBR plugins and Deputy's custom plugins pass through
	scalibrPlugins, err := pl.FromNames([]string{"go/gomod", "javascript/packagejson"})
	if err != nil {
		t.Fatalf("pl.FromNames: %v", err)
	}
	plugins := append(scalibrPlugins, ghactions.New())

	filtered := filterInventoryPlugins(plugins)
	if len(filtered) != 3 {
		names := make([]string, len(filtered))
		for i, p := range filtered {
			names[i] = p.Name()
		}
		t.Fatalf("expected 3 plugins, got %d: %v", len(filtered), names)
	}

	// Verify all expected plugins are present
	found := make(map[string]bool)
	for _, p := range filtered {
		found[p.Name()] = true
	}
	expected := []string{"go/gomod", "javascript/packagejson", ghactions.Name}
	for _, name := range expected {
		if !found[name] {
			t.Errorf("expected plugin %q not found in filtered results", name)
		}
	}
}
