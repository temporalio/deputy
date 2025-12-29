package render

import (
	"bytes"
	"strings"
	"testing"
)

func TestDisplayVulnerabilities_NoVulns(t *testing.T) {
	var buf bytes.Buffer
	DisplayVulnerabilities(&buf, nil)
	out := buf.String()
	if !strings.Contains(out, "No vulnerabilities found") {
		t.Fatalf("expected output to mention no vulns, got %q", out)
	}
}
