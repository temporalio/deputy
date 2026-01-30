package nixstore

import (
	"strings"
	"testing"
)

// realHash is a valid 32-char base32 hash from an actual Nix store path
// Nix base32 alphabet: 0123456789abcdfghjklmnpqrsvwxyz (no e, i, o, u, t)
const realHash = "0c0msqmxpnbsrzpxnzgfv2p8p8p0y0wb"

// makeValidStorePath creates a valid Nix store path for testing
func makeValidStorePath(hash, name string) string {
	return "/nix/store/" + hash + "-" + name
}

// TestParseDerivationBasic tests basic derivation parsing with minimal validation
func TestParseDerivationBasic(t *testing.T) {
	// This test uses a real-looking hash and simple output that should pass validation
	outPath := makeValidStorePath(realHash, "hello-2.10")

	// Minimal derivation with just one output and no input derivations
	drvContent := `Derive([("out","` + outPath + `","","")],` +
		`[],` + // no input derivations
		`[],` + // no input sources
		`"x86_64-linux",` +
		`"/bin/sh",` +
		`[],` +
		`[("name","hello"),("out","` + outPath + `"),("system","x86_64-linux")])`

	drv, err := ParseDerivation(strings.NewReader(drvContent), "/nix/store/test.drv")
	if err != nil {
		t.Fatalf("ParseDerivation failed: %v", err)
	}

	// Check basic fields
	if drv.Name != "hello" {
		t.Errorf("Name = %q, want %q", drv.Name, "hello")
	}

	if drv.System != "x86_64-linux" {
		t.Errorf("System = %q, want %q", drv.System, "x86_64-linux")
	}

	if drv.Builder != "/bin/sh" {
		t.Errorf("Builder = %q, want %q", drv.Builder, "/bin/sh")
	}

	// Check outputs
	if len(drv.Outputs) != 1 {
		t.Errorf("len(Outputs) = %d, want 1", len(drv.Outputs))
	}
	if drv.Outputs["out"] != outPath {
		t.Errorf("Outputs[out] = %q, want %q", drv.Outputs["out"], outPath)
	}
}

func TestDerivationOutputPath(t *testing.T) {
	outPath := makeValidStorePath(realHash, "hello-2.10")
	devPath := makeValidStorePath("1c0msqmxpnbsrzpxnzgfv2p8p8p0y0wb", "hello-2.10-dev")

	drvContent := `Derive([("dev","` + devPath + `","",""),("out","` + outPath + `","","")],` +
		`[],` +
		`[],` +
		`"x86_64-linux",` +
		`"/bin/sh",` +
		`[],` +
		`[("name","hello"),("out","` + outPath + `")])`

	drv, err := ParseDerivation(strings.NewReader(drvContent), "/nix/store/test.drv")
	if err != nil {
		t.Fatalf("ParseDerivation failed: %v", err)
	}

	tests := []struct {
		output string
		want   string
	}{
		{"", outPath},    // default to "out"
		{"out", outPath}, // explicit out
		{"dev", devPath}, // dev output
		{"lib", ""},      // non-existent
	}

	for _, tc := range tests {
		got := drv.OutputPath(tc.output)
		if got != tc.want {
			t.Errorf("OutputPath(%q) = %q, want %q", tc.output, got, tc.want)
		}
	}
}

func TestDerivationStore(t *testing.T) {
	store := NewDerivationStore()

	out1 := makeValidStorePath("2c0msqmxpnbsrzpxnzgfv2p8p8p0y0wb", "hello-1.0")
	drv1Path := makeValidStorePath("3c0msqmxpnbsrzpxnzgfv2p8p8p0y0wb", "hello-1.0.drv")

	// Add a derivation
	drv1Content := `Derive([("out","` + out1 + `","","")],` +
		`[],` +
		`[],` +
		`"x86_64-linux",` +
		`"/bin/sh",` +
		`[],` +
		`[("name","hello"),("out","` + out1 + `")])`

	drv1, err := ParseDerivation(strings.NewReader(drv1Content), drv1Path)
	if err != nil {
		t.Fatalf("ParseDerivation drv1 failed: %v", err)
	}

	store.Add(drv1)

	// Test Get
	if got := store.Get(drv1Path); got != drv1 {
		t.Error("Get didn't return expected derivation")
	}

	// Test GetByOutputPath
	if got := store.GetByOutputPath(out1); got != drv1 {
		t.Error("GetByOutputPath didn't return expected derivation")
	}

	// Test All
	all := store.All()
	if len(all) != 1 {
		t.Errorf("len(All()) = %d, want 1", len(all))
	}
}

func TestDerivationDependencies(t *testing.T) {
	out := makeValidStorePath(realHash, "hello-2.10")
	dep1Drv := makeValidStorePath("4c0msqmxpnbsrzpxnzgfv2p8p8p0y0wb", "dep1.drv")

	drvContent := `Derive([("out","` + out + `","","")],` +
		`[("` + dep1Drv + `",["out"])],` +
		`[],` +
		`"x86_64-linux",` +
		`"/bin/sh",` +
		`[],` +
		`[("name","hello"),("out","` + out + `")])`

	drv, err := ParseDerivation(strings.NewReader(drvContent), "/nix/store/test.drv")
	if err != nil {
		t.Fatalf("ParseDerivation failed: %v", err)
	}

	deps := drv.Dependencies()
	if len(deps) != 1 {
		t.Errorf("len(Dependencies()) = %d, want 1", len(deps))
	}

	if len(deps) >= 1 && deps[0].Path != dep1Drv {
		t.Errorf("deps[0].Path = %q, want %q", deps[0].Path, dep1Drv)
	}
}

func TestDerivationStoreFindDependencies(t *testing.T) {
	store := NewDerivationStore()

	out1 := makeValidStorePath("5c0msqmxpnbsrzpxnzgfv2p8p8p0y0wb", "pkg1")
	out2 := makeValidStorePath("6c0msqmxpnbsrzpxnzgfv2p8p8p0y0wb", "pkg2")
	drv1Path := makeValidStorePath("7c0msqmxpnbsrzpxnzgfv2p8p8p0y0wb", "pkg1.drv")
	drv2Path := makeValidStorePath("8c0msqmxpnbsrzpxnzgfv2p8p8p0y0wb", "pkg2.drv")

	// Build a simple dependency: pkg2 -> pkg1
	drv1Content := `Derive([("out","` + out1 + `","","")],` +
		`[],` +
		`[],` +
		`"x86_64-linux",` +
		`"/bin/sh",` +
		`[],` +
		`[("name","pkg1"),("out","` + out1 + `")])`

	drv2Content := `Derive([("out","` + out2 + `","","")],` +
		`[("` + drv1Path + `",["out"])],` +
		`[],` +
		`"x86_64-linux",` +
		`"/bin/sh",` +
		`[],` +
		`[("name","pkg2"),("out","` + out2 + `")])`

	drv1, err := ParseDerivation(strings.NewReader(drv1Content), drv1Path)
	if err != nil {
		t.Fatalf("ParseDerivation drv1 failed: %v", err)
	}
	drv2, err := ParseDerivation(strings.NewReader(drv2Content), drv2Path)
	if err != nil {
		t.Fatalf("ParseDerivation drv2 failed: %v", err)
	}

	store.Add(drv1)
	store.Add(drv2)

	// Find deps of pkg2 - should be pkg1
	deps := store.FindDependencies(out2)
	if len(deps) != 1 || deps[0] != out1 {
		t.Errorf("FindDependencies(pkg2) = %v, want [%s]", deps, out1)
	}

	// Find deps of pkg1 - should be empty
	deps = store.FindDependencies(out1)
	if len(deps) != 0 {
		t.Errorf("FindDependencies(pkg1) = %v, want []", deps)
	}
}

func TestParseInvalidDerivation(t *testing.T) {
	invalidDrvs := []string{
		"",           // empty
		"NotDerive",  // wrong prefix
		"Derive(",    // incomplete
		"Derive([])", // missing fields
	}

	for _, drvContent := range invalidDrvs {
		_, err := ParseDerivation(strings.NewReader(drvContent), "/test.drv")
		if err == nil {
			t.Errorf("ParseDerivation(%q) should have failed", drvContent)
		}
	}
}
