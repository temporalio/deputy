package cmd

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	dependencyv1 "github.com/picatz/deputy/gen/deputy/dependency/v1"
	scanv1 "github.com/picatz/deputy/gen/deputy/scan/v1"
	targetv1 "github.com/picatz/deputy/gen/deputy/target/v1"
	vulnerabilityv1 "github.com/picatz/deputy/gen/deputy/vulnerability/v1"
	"github.com/spf13/cobra"
)

func newTestRoot(out, errW *bytes.Buffer) *cobra.Command {
	root := &cobra.Command{
		Use:           "deputy",
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	root.SetOut(out)
	root.SetErr(errW)
	RegisterCommands(root, Dependencies{})
	return root
}

// writeScanResponseProtoFile writes a proto ScanResponse to a temp file for testing.
func writeScanResponseProtoFile(t *testing.T, resp *scanv1.ScanResponse) string {
	t.Helper()

	opts := protojson.MarshalOptions{
		Multiline:       true,
		Indent:          "  ",
		EmitUnpopulated: false,
		UseProtoNames:   true,
	}
	data, err := opts.Marshal(resp)
	if err != nil {
		t.Fatalf("encode report: %v", err)
	}

	path := t.TempDir() + "/scan-report.json"
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("write report: %v", err)
	}
	return path
}

func TestCLIOutput_TriageFromReport_WritesToCommandOut(t *testing.T) {
	// This test validates that output goes to the command's stdout, not os.Stdout.
	// The triage command parses proto JSON format from scan command output.
	resp := &scanv1.ScanResponse{
		Target: &targetv1.Target{
			DisplayPath: "github.com/acme/repo",
			CommitHash:  "deadbeef",
		},
		Findings: []*vulnerabilityv1.Finding{
			{
				AdvisoryId: "OSV-TEST-1",
				Package: &dependencyv1.Package{
					Name:      "github.com/acme/mod",
					Version:   "v1.0.0",
					Ecosystem: "Go",
					Direct:    true,
				},
				Advisory: &vulnerabilityv1.Advisory{
					Id:      "OSV-TEST-1",
					Summary: "Test vulnerability",
					Severity: &vulnerabilityv1.Severity{
						Score: 9.8,
						Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_CRITICAL,
						Type:  vulnerabilityv1.SeverityType_SEVERITY_TYPE_CVSS_V3,
					},
					FixedVersions: []string{"v1.0.1"},
				},
			},
		},
		Stats: &vulnerabilityv1.Stats{
			Unique:       1,
			High:         1,
			FixAvailable: 1,
		},
	}
	path := writeScanResponseProtoFile(t, resp)

	var out, errBuf bytes.Buffer
	root := newTestRoot(&out, &errBuf)
	root.SetArgs([]string{"triage", "--report", path, "--format", "text"})
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}

	if errBuf.Len() != 0 {
		t.Fatalf("unexpected stderr: %q", errBuf.String())
	}
	got := out.String()
	// Verify output goes to stdout (the main goal of this test)
	if !strings.Contains(got, "Triage Summary:") {
		t.Fatalf("expected stdout to contain 'Triage Summary:', got %q", got)
	}
}

func TestCLIOutput_FixFromReport_WritesToCommandOut(t *testing.T) {
	resp := &scanv1.ScanResponse{
		Target: &targetv1.Target{
			DisplayPath: "github.com/acme/repo",
			CommitHash:  "deadbeef",
		},
		Findings: []*vulnerabilityv1.Finding{
			{
				AdvisoryId: "OSV-TEST-1",
				Package: &dependencyv1.Package{
					Name:      "github.com/acme/mod",
					Version:   "v1.0.0",
					Ecosystem: "Go",
					Direct:    true,
				},
				Advisory: &vulnerabilityv1.Advisory{
					Id:      "OSV-TEST-1",
					Summary: "Test vulnerability",
					Severity: &vulnerabilityv1.Severity{
						Score: 9.8,
						Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_CRITICAL,
						Type:  vulnerabilityv1.SeverityType_SEVERITY_TYPE_CVSS_V3,
					},
					FixedVersions: []string{"v1.0.1"},
				},
			},
		},
		Stats: &vulnerabilityv1.Stats{
			Unique:       1,
			High:         1,
			FixAvailable: 1,
		},
	}
	path := writeScanResponseProtoFile(t, resp)

	var out, errBuf bytes.Buffer
	root := newTestRoot(&out, &errBuf)
	root.SetArgs([]string{"fix", "--report", path, "--format", "text"})
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}

	if errBuf.Len() != 0 {
		t.Fatalf("unexpected stderr: %q", errBuf.String())
	}
	got := out.String()
	if !strings.Contains(got, "Remediation Plan:") {
		t.Fatalf("expected stdout to contain remediation header, got %q", got)
	}
}

