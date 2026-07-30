package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/spf13/cobra"
	fixv1 "github.com/temporalio/deputy/gen/deputy/fix/v1"
	targetv1 "github.com/temporalio/deputy/gen/deputy/target/v1"
	internalproto "github.com/temporalio/deputy/internal/proto"
	remediation "github.com/temporalio/deputy/internal/remediation"
)

func TestBuildFixResponse(t *testing.T) {
	commands := []remediation.Command{
		{Command: "go get example.com/mod@v1.2.3", Executable: true},
		{Command: "Edit Gemfile to require foo >= 2.0.0", Executable: false},
		{Command: "go get go@1.22.3", Executable: true},
	}
	resp := internalproto.BuildFixResponse(&targetv1.Target{
		DisplayPath:  "github.com/example/project",
		Ref:          "main",
		EffectiveRef: "main",
		CommitHash:   "abcdef0",
	}, "v1.22.3", commands)
	if resp.Target.DisplayPath != "github.com/example/project" {
		t.Fatalf("plan target mismatch: %+v", resp.Target)
	}
	if resp.StdlibUpgrade != "v1.22.3" {
		t.Fatalf("expected stdlib v1.22.3, got %q", resp.StdlibUpgrade)
	}
	if resp.Stats.TotalCommands != 3 {
		t.Fatalf("expected total commands 3, got %d", resp.Stats.TotalCommands)
	}
	if resp.Stats.RunnableCommands != 2 {
		t.Fatalf("expected runnable commands 2, got %d", resp.Stats.RunnableCommands)
	}
}

func TestOutputFixProtoJSON(t *testing.T) {
	resp := &fixv1.FixResponse{
		Target:        &targetv1.Target{DisplayPath: "repo", CommitHash: "abc"},
		StdlibUpgrade: "v1.2.0",
		Commands: []*fixv1.RemediationCommand{
			{Command: "npm install foo@1", Executable: true},
		},
		Stats: &fixv1.RemediationStats{TotalCommands: 1, RunnableCommands: 1},
	}
	var buf bytes.Buffer
	if err := outputFixProtoJSON(&buf, resp); err != nil {
		t.Fatalf("outputFixProtoJSON returned error: %v", err)
	}
	var roundTrip fixv1.FixResponse
	if err := protojson.Unmarshal(buf.Bytes(), &roundTrip); err != nil {
		t.Fatalf("failed to unmarshal plan json: %v", err)
	}
	if roundTrip.StdlibUpgrade != resp.StdlibUpgrade || roundTrip.Stats.RunnableCommands != resp.Stats.RunnableCommands {
		t.Fatalf("round-trip mismatch: %+v vs %+v", &roundTrip, resp)
	}
}

func TestReadFixPlanProtoFromReader(t *testing.T) {
	resp := &fixv1.FixResponse{
		Target:        &targetv1.Target{DisplayPath: "repo", CommitHash: "abc"},
		StdlibUpgrade: "v1.0.0",
		Commands: []*fixv1.RemediationCommand{
			{Command: "go get example.com/foo@v1.2.3", Executable: true},
			{Command: "Edit Gemfile", Executable: false},
		},
		Stats: &fixv1.RemediationStats{TotalCommands: 2, RunnableCommands: 1},
	}
	var buf bytes.Buffer
	if err := outputFixProtoJSON(&buf, resp); err != nil {
		t.Fatalf("failed to encode plan: %v", err)
	}
	got, err := readFixPlanProto(bytes.NewReader(buf.Bytes()), "-")
	if err != nil {
		t.Fatalf("readFixPlanProto returned error: %v", err)
	}
	if got.Stats.TotalCommands != int32(len(got.Commands)) {
		t.Fatalf("expected stats to refresh, got %+v", got.Stats)
	}
}

// TestBuildFixFromReportIgnoresUnrelatedCwdRules guards imported reports
// against the caller's working directory: a .deputyignore.yaml in an
// unrelated repository must not silently drop remediation commands from a
// report produced elsewhere. Only an explicit --ignore-file applies.
func TestBuildFixFromReportIgnoresUnrelatedCwdRules(t *testing.T) {
	report := `{
		"target": {"displayPath": "github.com/example/project"},
		"findings": [{
			"advisoryId": "CVE-2026-1111",
			"affected": true,
			"package": {"name": "github.com/example/widget", "version": "v1.0.0", "ecosystem": "go", "purl": "pkg:golang/github.com/example/widget@v1.0.0", "direct": true, "manifestRefs": [{"path": "go.mod", "manager": "go"}]}
		}],
		"advisories": {
			"CVE-2026-1111": {
				"id": "CVE-2026-1111",
				"fixedVersions": ["v1.1.0"],
				"packageFixes": [{"module": "github.com/example/widget", "ecosystem": "Go", "fixedVersions": ["v1.1.0"]}]
			}
		}
	}`

	dir := t.TempDir()
	rules := "ignore:\n  - package: github.com/example/widget\n    ecosystem: go\n    reason: unrelated repo suppression\n"
	if err := os.WriteFile(filepath.Join(dir, ".deputyignore.yaml"), []byte(rules), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)

	cmd := &cobra.Command{}
	cmd.Flags().String("ignore-file", "", "")

	resp, err := buildFixFromReport(cmd, strings.NewReader(report), "-", false)
	if err != nil {
		t.Fatalf("buildFixFromReport: %v", err)
	}
	if len(resp.Commands) == 0 {
		t.Fatal("expected remediation commands: the cwd's ignore rules must not filter an imported report")
	}
}
