package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestCapabilitiesReferenceRefAwarePlanningCommands(t *testing.T) {
	const supported = "\u2713"

	root := &cobra.Command{Use: "deputy"}
	AddFixCommand(root, nil)
	AddTriageCommand(root, nil)

	matrix := readCommandFeatureMatrix(t)
	for _, name := range []string{"fix", "triage"} {
		cmd, _, err := root.Find([]string{name})
		if err != nil {
			t.Fatalf("Find(%q): %v", name, err)
		}
		if cmd.Flags().Lookup("ref") == nil {
			t.Fatalf("%s command does not expose --ref", name)
		}
		if got := matrix["Git ref targeting"][name]; got != supported {
			t.Fatalf("capabilities.md Git ref targeting for %s = %q, want supported mark", name, got)
		}
		if got := matrix["Remote repos"][name]; got != supported {
			t.Fatalf("capabilities.md Remote repos for %s = %q, want supported mark", name, got)
		}
	}
}

func readCommandFeatureMatrix(t *testing.T) map[string]map[string]string {
	t.Helper()

	docPath := filepath.Join("..", "..", "..", "docs", "reference", "capabilities.md")
	data, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("ReadFile(%q): %v", docPath, err)
	}

	var headers []string
	matrix := map[string]map[string]string{}
	inTable := false
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "| Feature |") {
			headers = markdownTableCells(line)
			inTable = true
			continue
		}
		if !inTable {
			continue
		}
		if strings.TrimSpace(line) == "" {
			break
		}
		cells := markdownTableCells(line)
		if len(cells) != len(headers) {
			continue
		}
		feature := strings.Trim(cells[0], "* ")
		if feature == "" || strings.Contains(feature, "---") {
			continue
		}
		row := map[string]string{}
		for i := 1; i < len(headers); i++ {
			row[headers[i]] = cells[i]
		}
		matrix[feature] = row
	}
	if len(matrix) == 0 {
		t.Fatalf("did not parse Command Feature Matrix from %s", docPath)
	}
	return matrix
}

func markdownTableCells(line string) []string {
	line = strings.TrimSpace(line)
	line = strings.TrimPrefix(line, "|")
	line = strings.TrimSuffix(line, "|")
	parts := strings.Split(line, "|")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}
