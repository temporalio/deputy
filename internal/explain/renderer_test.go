package explain

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestExtractCVSSInfo(t *testing.T) {
	tests := []struct {
		name       string
		vuln       *osvschema.Vulnerability
		wantVector string
		wantScore  float64
	}{
		{
			name:       "nil vuln",
			vuln:       nil,
			wantVector: "",
			wantScore:  0,
		},
		{
			name: "prefers CVSS v3 over v2",
			vuln: &osvschema.Vulnerability{
				Severity: []*osvschema.Severity{
					{Type: osvschema.Severity_CVSS_V2, Score: "AV:N/AC:L/Au:N/C:P/I:P/A:P"},
					{Type: osvschema.Severity_CVSS_V3, Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
				},
			},
			wantVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			wantScore:  9.8,
		},
		{
			// CVSS v2 is selected as the fallback (vector returned), but the
			// score parser only understands v3/v4 vectors, so it returns -1.
			// This documents current behavior; v2 numeric scoring is unsupported.
			name: "falls back to v2 when no v3/v4",
			vuln: &osvschema.Vulnerability{
				Severity: []*osvschema.Severity{
					{Type: osvschema.Severity_CVSS_V2, Score: "AV:N/AC:L/Au:N/C:P/I:P/A:P"},
				},
			},
			wantVector: "AV:N/AC:L/Au:N/C:P/I:P/A:P",
			wantScore:  -1,
		},
		{
			name:       "no severity entries",
			vuln:       &osvschema.Vulnerability{},
			wantVector: "",
			wantScore:  0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			vector, score := extractCVSSInfo(tc.vuln)
			if vector != tc.wantVector {
				t.Errorf("vector = %q, want %q", vector, tc.wantVector)
			}
			if score != tc.wantScore {
				t.Errorf("score = %v, want %v", score, tc.wantScore)
			}
		})
	}
}

func TestDeriveSeverity(t *testing.T) {
	tests := []struct {
		name  string
		score float64
		vuln  *osvschema.Vulnerability
		want  string
	}{
		{"critical", 9.8, nil, "CRITICAL"},
		{"critical boundary", 9.0, nil, "CRITICAL"},
		{"high", 7.5, nil, "HIGH"},
		{"high boundary", 7.0, nil, "HIGH"},
		{"medium", 5.0, nil, "MEDIUM"},
		{"medium boundary", 4.0, nil, "MEDIUM"},
		{"low", 2.0, nil, "LOW"},
		{
			name:  "zero score falls back to GHSA database_specific",
			score: 0,
			vuln: &osvschema.Vulnerability{
				DatabaseSpecific: osvStruct(map[string]any{"severity": "high"}),
			},
			want: "HIGH",
		},
		{
			name:  "zero score with no fallback is UNKNOWN",
			score: 0,
			vuln:  &osvschema.Vulnerability{},
			want:  "UNKNOWN",
		},
		{"zero score nil vuln is UNKNOWN", 0, nil, "UNKNOWN"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := deriveSeverity(tc.score, tc.vuln)
			if got != tc.want {
				t.Errorf("deriveSeverity(%v) = %q, want %q", tc.score, got, tc.want)
			}
		})
	}
}

func TestFindCVEID(t *testing.T) {
	tests := []struct {
		name string
		vuln *osvschema.Vulnerability
		want string
	}{
		{"nil", nil, ""},
		{
			name: "ID is a CVE",
			vuln: &osvschema.Vulnerability{Id: "CVE-2021-44228"},
			want: "CVE-2021-44228",
		},
		{
			name: "CVE found in aliases",
			vuln: &osvschema.Vulnerability{
				Id:      "GHSA-jfh8-c2jp-5v3q",
				Aliases: []string{"CVE-2021-44228"},
			},
			want: "CVE-2021-44228",
		},
		{
			name: "no CVE anywhere",
			vuln: &osvschema.Vulnerability{
				Id:      "GHSA-jfh8-c2jp-5v3q",
				Aliases: []string{"GO-2021-0001"},
			},
			want: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := findCVEID(tc.vuln)
			if got != tc.want {
				t.Errorf("findCVEID = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestExtractCWEs(t *testing.T) {
	t.Run("nil vuln returns nil", func(t *testing.T) {
		if got := extractCWEs(nil); got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})

	t.Run("no database_specific returns nil", func(t *testing.T) {
		if got := extractCWEs(&osvschema.Vulnerability{}); got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})

	t.Run("extracts cwe_ids", func(t *testing.T) {
		vuln := &osvschema.Vulnerability{
			DatabaseSpecific: osvStruct(map[string]any{
				"cwe_ids": []any{"CWE-79", "CWE-89"},
			}),
		}
		got := extractCWEs(vuln)
		if len(got) != 2 {
			t.Fatalf("expected 2 CWEs, got %d: %+v", len(got), got)
		}
		if got[0].ID != "CWE-79" {
			t.Errorf("first CWE ID = %q, want CWE-79", got[0].ID)
		}
	})
}

// TestRenderJSON_GoldenShape exercises the full buildVulnData → JSON path,
// which covers the osvschema field access (ID, References, Affected, Severity)
// touched during the protobuf migration. It asserts on stable JSON keys rather
// than exact formatting.
func TestRenderJSON_GoldenShape(t *testing.T) {
	vuln := &osvschema.Vulnerability{
		Id:      "GHSA-jfh8-c2jp-5v3q",
		Aliases: []string{"CVE-2021-44228"},
		Summary: "Log4Shell",
		Details: "Remote code execution in Apache Log4j2.",
		Severity: []*osvschema.Severity{
			{Type: osvschema.Severity_CVSS_V3, Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"},
		},
		References: []*osvschema.Reference{
			{Type: osvschema.Reference_ADVISORY, Url: "https://example.com/advisory"},
			{Type: osvschema.Reference_WEB, Url: "https://example.com/blog"},
		},
		DatabaseSpecific: osvStruct(map[string]any{
			"cwe_ids": []any{"CWE-502"},
		}),
	}

	r := NewRenderer(Config{Enrich: false})
	var buf bytes.Buffer
	if err := r.RenderJSON(t.Context(), &buf, vuln); err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}

	var out map[string]any
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}

	if out["id"] != "GHSA-jfh8-c2jp-5v3q" {
		t.Errorf("id = %v, want GHSA-jfh8-c2jp-5v3q", out["id"])
	}
	// severity is a rich object; assert its derived level.
	sevObj, ok := out["severity"].(map[string]any)
	if !ok {
		t.Fatalf("severity is not an object: %v", out["severity"])
	}
	if lvl, _ := sevObj["level"].(string); !strings.EqualFold(lvl, "CRITICAL") {
		t.Errorf("severity.level = %v, want CRITICAL", sevObj["level"])
	}
}

func TestRender_NilVulnIsNoOp(t *testing.T) {
	r := NewRenderer(Config{})
	var buf bytes.Buffer
	if err := r.Render(t.Context(), &buf, nil); err != nil {
		t.Fatalf("Render(nil): %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("expected no output for nil vuln, got %q", buf.String())
	}
}

func TestRender_TextSmoke(t *testing.T) {
	vuln := &osvschema.Vulnerability{
		Id:      "CVE-2021-44228",
		Summary: "Log4Shell",
		Severity: []*osvschema.Severity{
			{Type: osvschema.Severity_CVSS_V3, Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"},
		},
		References: []*osvschema.Reference{
			{Type: osvschema.Reference_ADVISORY, Url: "https://example.com/advisory"},
		},
	}

	r := NewRenderer(Config{Enrich: false})
	var buf bytes.Buffer
	if err := r.Render(t.Context(), &buf, vuln); err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "CVE-2021-44228") {
		t.Errorf("expected vuln ID in output, got:\n%s", out)
	}
}

// osvStruct builds the protobuf Struct an OSV record carries in its
// database_specific field. A value the Struct cannot represent is a bug in the
// fixture, so it panics rather than returning an error.
func osvStruct(fields map[string]any) *structpb.Struct {
	s, err := structpb.NewStruct(fields)
	if err != nil {
		panic(err)
	}
	return s
}

// TestRender_AbsentDatesRenderAsAbsent pins the one non-mechanical part of the
// osv-schema protobuf migration: published/modified are now nil pointers when a
// record omits them, and Timestamp.AsTime turns nil into the Unix epoch. The
// timeline must stay silent rather than claim a 1970 disclosure date.
func TestRender_AbsentDatesRenderAsAbsent(t *testing.T) {
	dated := timestamppb.New(time.Date(2021, 12, 10, 0, 0, 0, 0, time.UTC))
	tests := []struct {
		name      string
		published *timestamppb.Timestamp
		modified  *timestamppb.Timestamp
		wantDates bool
	}{
		{name: "both absent"},
		{name: "published only", published: dated, wantDates: true},
		{name: "modified only", modified: dated, wantDates: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vuln := &osvschema.Vulnerability{
				Id:        "CVE-2021-44228",
				Summary:   "Log4Shell",
				Published: tt.published,
				Modified:  tt.modified,
			}
			var buf bytes.Buffer
			if err := NewRenderer(Config{}).Render(t.Context(), &buf, vuln); err != nil {
				t.Fatalf("Render: %v", err)
			}
			out := buf.String()
			if got := strings.Contains(out, "Timeline"); got != tt.wantDates {
				t.Errorf("timeline section present = %v, want %v; output:\n%s", got, tt.wantDates, out)
			}
			for _, epoch := range []string{"1970-01-01", "0001-01-01"} {
				if strings.Contains(out, epoch) {
					t.Errorf("output rendered an absent date as %s:\n%s", epoch, out)
				}
			}
		})
	}
}

// TestRenderJSONWeaknessURL pins how the JSON output links a CWE to MITRE. The
// link is derived by parsing the identifier, so a malformed one yields no link
// rather than a URL that resolves to nothing.
func TestRenderJSONWeaknessURL(t *testing.T) {
	tests := []struct {
		name    string
		cweID   string
		wantURL string
	}{
		{"well formed", "CWE-89", "https://cwe.mitre.org/data/definitions/89.html"},
		{"bare number is normalized", "89", "https://cwe.mitre.org/data/definitions/89.html"},
		{"non-numeric suffix yields no link", "CWE-abc", ""},
		{"zero is not a CWE", "CWE-0", ""},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewRenderer(Config{})
			data := &VulnData{
				Vuln: &osvschema.Vulnerability{Id: "GHSA-test"},
				CWEs: []CWEInfo{{ID: tt.cweID, Name: "name"}},
			}

			var buf bytes.Buffer
			if err := r.renderJSON(&buf, data); err != nil {
				t.Fatalf("renderJSON: %v", err)
			}

			var got struct {
				Weaknesses []struct {
					ID  string `json:"id"`
					URL string `json:"url"`
				} `json:"weaknesses"`
			}
			if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
				t.Fatalf("unmarshal %s: %v", buf.String(), err)
			}
			if len(got.Weaknesses) != 1 {
				t.Fatalf("got %d weaknesses, want 1", len(got.Weaknesses))
			}
			if got.Weaknesses[0].URL != tt.wantURL {
				t.Errorf("url for %q = %q, want %q", tt.cweID, got.Weaknesses[0].URL, tt.wantURL)
			}
		})
	}
}

// TestRenderJSON_AbsentDatesOmitTimeline is [TestRender_AbsentDatesRenderAsAbsent]
// for the JSON surface: an absent date must not produce a timeline key at all,
// because a consumer cannot tell an epoch date from a missing one.
func TestRenderJSON_AbsentDatesOmitTimeline(t *testing.T) {
	vuln := &osvschema.Vulnerability{Id: "CVE-2021-44228", Summary: "Log4Shell"}
	var buf bytes.Buffer
	if err := NewRenderer(Config{}).RenderJSON(t.Context(), &buf, vuln); err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	if _, ok := out["timeline"]; ok {
		t.Errorf("timeline = %v, want the key omitted when both dates are absent", out["timeline"])
	}
}
