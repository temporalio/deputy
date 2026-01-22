package inventory

import (
	"testing"

	"github.com/google/osv-scalibr/plugin"
	pl "github.com/google/osv-scalibr/plugin/list"

	dockerfilex "github.com/picatz/deputy/internal/inventory/plugins/docker/dockerfilex"
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

func TestResolvePluginsOnlyGitHubActions(t *testing.T) {
	// When user specifies only github-actions, only the GitHub Actions plugin
	// should be returned, not all SCALIBR plugins.
	opts := ScanOptions{Ecosystems: []string{"github-actions"}}
	cap := &plugin.Capabilities{OS: plugin.OSLinux}

	plugins, err := resolvePlugins(opts, cap)
	if err != nil {
		t.Fatalf("resolvePlugins: %v", err)
	}

	if len(plugins) != 1 {
		names := make([]string, len(plugins))
		for i, p := range plugins {
			names[i] = p.Name()
		}
		t.Fatalf("expected 1 plugin (github-actions only), got %d: %v", len(plugins), names)
	}

	if plugins[0].Name() != ghactions.Name {
		t.Errorf("expected %s plugin, got %s", ghactions.Name, plugins[0].Name())
	}
}

func TestResolvePluginsOnlyDockerfile(t *testing.T) {
	// When user specifies only dockerfile, only the Dockerfile plugin
	// should be returned, not all SCALIBR plugins.
	opts := ScanOptions{Ecosystems: []string{"dockerfile"}}
	cap := &plugin.Capabilities{OS: plugin.OSLinux}

	plugins, err := resolvePlugins(opts, cap)
	if err != nil {
		t.Fatalf("resolvePlugins: %v", err)
	}

	if len(plugins) != 1 {
		names := make([]string, len(plugins))
		for i, p := range plugins {
			names[i] = p.Name()
		}
		t.Fatalf("expected 1 plugin (dockerfile only), got %d: %v", len(plugins), names)
	}

	if plugins[0].Name() != dockerfilex.Name {
		t.Errorf("expected %s plugin, got %s", dockerfilex.Name, plugins[0].Name())
	}
}

func TestResolvePluginsBothInternalEcosystems(t *testing.T) {
	// When user specifies both github-actions and dockerfile, only those
	// two plugins should be returned.
	opts := ScanOptions{Ecosystems: []string{"github-actions", "dockerfile"}}
	cap := &plugin.Capabilities{OS: plugin.OSLinux}

	plugins, err := resolvePlugins(opts, cap)
	if err != nil {
		t.Fatalf("resolvePlugins: %v", err)
	}

	if len(plugins) != 2 {
		names := make([]string, len(plugins))
		for i, p := range plugins {
			names[i] = p.Name()
		}
		t.Fatalf("expected 2 plugins, got %d: %v", len(plugins), names)
	}

	found := make(map[string]bool)
	for _, p := range plugins {
		found[p.Name()] = true
	}
	if !found[ghactions.Name] {
		t.Errorf("expected %s plugin not found", ghactions.Name)
	}
	if !found[dockerfilex.Name] {
		t.Errorf("expected %s plugin not found", dockerfilex.Name)
	}
}

func TestResolvePluginsExternalWithGitHubActions(t *testing.T) {
	// When user specifies go and github-actions, both should be included.
	opts := ScanOptions{Ecosystems: []string{"go", "github-actions"}}
	cap := &plugin.Capabilities{OS: plugin.OSLinux}

	plugins, err := resolvePlugins(opts, cap)
	if err != nil {
		t.Fatalf("resolvePlugins: %v", err)
	}

	// Should have go plugins + github-actions
	found := make(map[string]bool)
	for _, p := range plugins {
		found[p.Name()] = true
	}

	if !found[ghactions.Name] {
		t.Errorf("expected %s plugin not found", ghactions.Name)
	}
	// Should have at least one go plugin
	hasGo := false
	for name := range found {
		if len(name) > 3 && name[:3] == "go/" {
			hasGo = true
			break
		}
	}
	if !hasGo {
		t.Errorf("expected at least one go plugin")
	}
}

func TestResolvePluginsAllIncludesEverything(t *testing.T) {
	// When user specifies "all", all plugins should be included.
	opts := ScanOptions{Ecosystems: []string{"all"}}
	cap := &plugin.Capabilities{OS: plugin.OSLinux}

	plugins, err := resolvePlugins(opts, cap)
	if err != nil {
		t.Fatalf("resolvePlugins: %v", err)
	}

	// Should have many plugins including github-actions
	if len(plugins) < 5 {
		t.Errorf("expected many plugins for 'all', got %d", len(plugins))
	}

	found := make(map[string]bool)
	for _, p := range plugins {
		found[p.Name()] = true
	}

	if !found[ghactions.Name] {
		t.Errorf("expected %s plugin not found when using 'all'", ghactions.Name)
	}
}
