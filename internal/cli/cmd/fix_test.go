package cmd

import (
	"bytes"
	"encoding/json"
	"testing"

	remediation "github.com/picatz/deputy/internal/remediation"
)

func TestBuildRemediationPlan(t *testing.T) {
	scan := ScanResult{Repo: "github.com/example/project", Ref: "main", Commit: "abcdef0"}
	commands := []remediation.Command{
		{Command: "go get example.com/mod@v1.2.3", Executable: true},
		{Command: "Edit Gemfile to require foo >= 2.0.0", Executable: false},
	}
	plan := buildRemediationPlan(scan, commands, "v1.22.3")
	if plan.Target.Repo != scan.Repo || plan.Target.Ref != scan.Ref || plan.Target.Commit != scan.Commit {
		t.Fatalf("plan target mismatch: %+v", plan.Target)
	}
	if plan.StdlibUpgrade != "v1.22.3" {
		t.Fatalf("expected stdlib v1.22.3, got %q", plan.StdlibUpgrade)
	}
	if plan.Stats.TotalCommands != 2 {
		t.Fatalf("expected total commands 2, got %d", plan.Stats.TotalCommands)
	}
	if plan.Stats.RunnableCommands != 1 {
		t.Fatalf("expected runnable commands 1, got %d", plan.Stats.RunnableCommands)
	}
}

func TestOutputRemediationPlanJSON(t *testing.T) {
	plan := remediationPlan{
		Target:        remediationPlanTarget{Repo: "repo", Ref: "main", Commit: "abc"},
		StdlibUpgrade: "v1.2.0",
		Commands:      []remediation.Command{{Command: "npm install foo@1", Executable: true}},
		Stats:         remediationPlanSummary{TotalCommands: 1, RunnableCommands: 1},
	}
	var buf bytes.Buffer
	if err := outputRemediationPlanJSON(&buf, plan); err != nil {
		t.Fatalf("outputRemediationPlanJSON returned error: %v", err)
	}
	var roundTrip remediationPlan
	if err := json.Unmarshal(buf.Bytes(), &roundTrip); err != nil {
		t.Fatalf("failed to unmarshal plan json: %v", err)
	}
	if roundTrip.StdlibUpgrade != plan.StdlibUpgrade || roundTrip.Stats.RunnableCommands != plan.Stats.RunnableCommands {
		t.Fatalf("round-trip mismatch: %+v vs %+v", roundTrip, plan)
	}
}

func TestReadPlanSourceFromReader(t *testing.T) {
	plan := remediationPlan{
		Target:        remediationPlanTarget{Repo: "repo", Ref: "main", Commit: "abc"},
		StdlibUpgrade: "v1.0.0",
		Commands: []remediation.Command{
			{Command: "go get example.com/foo@v1.2.3", Executable: true},
			{Command: "Edit Gemfile", Executable: false},
		},
	}
	refreshRemediationPlanStats(&plan)
	var buf bytes.Buffer
	if err := outputRemediationPlanJSON(&buf, plan); err != nil {
		t.Fatalf("failed to encode plan: %v", err)
	}
	got, err := readPlanSource(bytes.NewReader(buf.Bytes()), "-")
	if err != nil {
		t.Fatalf("readPlanSource returned error: %v", err)
	}
	if got.Stats.TotalCommands != len(got.Commands) {
		t.Fatalf("expected stats to refresh, got %+v", got.Stats)
	}
}
