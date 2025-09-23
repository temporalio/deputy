package inventory

import (
	"testing"

	pl "github.com/google/osv-scalibr/plugin/list"
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
