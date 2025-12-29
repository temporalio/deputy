package render

import (
	"bytes"
	"strings"
	"testing"

	"github.com/picatz/deputy/internal/scan"
)

func TestDisplayVulnerabilities_NoVulns(t *testing.T) {
	var buf bytes.Buffer
	DisplayVulnerabilities(&buf, scan.Result{})
	out := buf.String()
	if !strings.Contains(out, "No vulnerabilities found") {
		t.Fatalf("expected output to mention no vulns, got %q", out)
	}
}
