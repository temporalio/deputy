package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/osv-scalibr/extractor"
	scalpurl "github.com/google/osv-scalibr/purl"

	"github.com/temporalio/deputy/internal/dependency"
	"github.com/temporalio/deputy/internal/inventory"
	sbomx "github.com/temporalio/deputy/internal/sbom"
)

// TestSBOMPolicyPayloadIsTheDeclaredContract pins that "deputy sbom --policy"
// hands policies the payload the binding registry documents: "packages" and
// "component"/"pkg" are deputy.dependency.v1.Package values, canonicalized like
// every other entrypoint's. The scanner's raw *extractor.Package is not a proto
// and not a CEL-adaptable struct, so leaving it in the payload made a field
// access on any of these variables fail outright.
func TestSBOMPolicyPayloadIsTheDeclaredContract(t *testing.T) {
	result := sbomx.Result{
		Target: inventory.Target{DisplayPath: "."},
		Direct: map[string]bool{"github.com/example/direct": true},
		Packages: []*extractor.Package{
			{
				Name:     "github.com/example/direct",
				Version:  "1.44.0",
				PURLType: scalpurl.TypeGolang,
				Location: dependency.NewPackageLocation("go.mod"),
			},
		},
	}

	tests := []struct {
		name       string
		entrypoint string
		when       string
	}{
		{
			name:       "report packages are canonical proto packages",
			entrypoint: "sbom_report",
			when:       `packages.exists(p, p.ecosystem == "go" && p.name == "github.com/example/direct" && p.version == "v1.44.0" && p.direct)`,
		},
		{
			name:       "component is a canonical proto package",
			entrypoint: "sbom_component",
			when:       `component.ecosystem == "go" && component.version == "v1.44.0"`,
		},
		{
			name:       "pkg aliases the component",
			entrypoint: "sbom_component",
			when:       `pkg.ecosystem == "go" && pkg.name == component.name`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeSBOMProbePolicy(t, tt.entrypoint, tt.when)
			var errW bytes.Buffer
			err := runSBOMPolicies(t.Context(), []string{path}, result, &errW)
			if err == nil {
				t.Fatalf("policy did not observe the declared contract; stderr: %s", errW.String())
			}
			if want := "matched"; !bytes.Contains([]byte(err.Error()), []byte(want)) {
				t.Fatalf("runSBOMPolicies error = %v, want a denial containing %q", err, want)
			}
		})
	}
}

// writeSBOMProbePolicy writes a single-rule bundle that denies when the
// expression holds, so a matched contract surfaces as a distinguishable error
// rather than as silence that an unevaluated policy would also produce.
func writeSBOMProbePolicy(t *testing.T, entrypoint, when string) string {
	t.Helper()
	body := "policies:\n" +
		"  - name: sbom-payload-probe\n" +
		"    entrypoints: [\"" + entrypoint + "\"]\n" +
		"    rules:\n" +
		"      - action: deny\n" +
		"        when: |\n" +
		"          " + when + "\n" +
		"        reason: \"matched\"\n"
	path := filepath.Join(t.TempDir(), "probe.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	return path
}
