package ignore

import (
	"testing"
	"time"
)

func TestRuleMatches(t *testing.T) {
	tests := []struct {
		name      string
		rule      Rule
		vulnID    string
		pkgName   string
		ecosystem string
		want      bool
	}{
		{
			name:      "exact id match",
			rule:      Rule{ID: "CVE-2021-44228"},
			vulnID:    "CVE-2021-44228",
			pkgName:   "log4j",
			ecosystem: "maven",
			want:      true,
		},
		{
			name:      "id match case insensitive",
			rule:      Rule{ID: "cve-2021-44228"},
			vulnID:    "CVE-2021-44228",
			pkgName:   "log4j",
			ecosystem: "maven",
			want:      true,
		},
		{
			name:      "id no match",
			rule:      Rule{ID: "CVE-2021-44228"},
			vulnID:    "CVE-2022-12345",
			pkgName:   "log4j",
			ecosystem: "maven",
			want:      false,
		},
		{
			name:      "exact package match",
			rule:      Rule{Package: "lodash"},
			vulnID:    "GHSA-xxxx",
			pkgName:   "lodash",
			ecosystem: "npm",
			want:      true,
		},
		{
			name:      "package match case insensitive",
			rule:      Rule{Package: "Lodash"},
			vulnID:    "GHSA-xxxx",
			pkgName:   "lodash",
			ecosystem: "npm",
			want:      true,
		},
		{
			name:      "package wildcard match",
			rule:      Rule{Package: "github.com/user/*"},
			vulnID:    "GHSA-xxxx",
			pkgName:   "github.com/user/repo",
			ecosystem: "go",
			want:      true,
		},
		{
			name:      "package wildcard exact prefix",
			rule:      Rule{Package: "github.com/user/*"},
			vulnID:    "GHSA-xxxx",
			pkgName:   "github.com/user",
			ecosystem: "go",
			want:      true,
		},
		{
			name:      "package wildcard no match",
			rule:      Rule{Package: "github.com/user/*"},
			vulnID:    "GHSA-xxxx",
			pkgName:   "github.com/other/repo",
			ecosystem: "go",
			want:      false,
		},
		{
			name:      "package trailing wildcard",
			rule:      Rule{Package: "lodash*"},
			vulnID:    "GHSA-xxxx",
			pkgName:   "lodash-es",
			ecosystem: "npm",
			want:      true,
		},
		{
			name:      "ecosystem match",
			rule:      Rule{Ecosystem: "npm"},
			vulnID:    "GHSA-xxxx",
			pkgName:   "lodash",
			ecosystem: "npm",
			want:      true,
		},
		{
			name:      "ecosystem no match",
			rule:      Rule{Ecosystem: "npm"},
			vulnID:    "GHSA-xxxx",
			pkgName:   "requests",
			ecosystem: "pypi",
			want:      false,
		},
		{
			name:      "multiple conditions all match",
			rule:      Rule{ID: "CVE-2021-44228", Package: "log4j", Ecosystem: "maven"},
			vulnID:    "CVE-2021-44228",
			pkgName:   "log4j",
			ecosystem: "maven",
			want:      true,
		},
		{
			name:      "multiple conditions one fails",
			rule:      Rule{ID: "CVE-2021-44228", Package: "log4j", Ecosystem: "npm"},
			vulnID:    "CVE-2021-44228",
			pkgName:   "log4j",
			ecosystem: "maven",
			want:      false,
		},
		{
			name:      "empty rule matches nothing",
			rule:      Rule{},
			vulnID:    "CVE-2021-44228",
			pkgName:   "log4j",
			ecosystem: "maven",
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.rule.Matches(tt.vulnID, tt.pkgName, tt.ecosystem)
			if got != tt.want {
				t.Errorf("Rule.Matches() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRuleExpiration(t *testing.T) {
	yesterday := time.Now().AddDate(0, 0, -1).Format("2006-01-02")
	tomorrow := time.Now().AddDate(0, 0, 1).Format("2006-01-02")

	tests := []struct {
		name    string
		rule    Rule
		want    bool
		expired bool
	}{
		{
			name:    "no expiration",
			rule:    Rule{ID: "CVE-2021-44228"},
			want:    true,
			expired: false,
		},
		{
			name:    "future expiration",
			rule:    Rule{ID: "CVE-2021-44228", Until: tomorrow},
			want:    true,
			expired: false,
		},
		{
			name:    "past expiration",
			rule:    Rule{ID: "CVE-2021-44228", Until: yesterday},
			want:    false,
			expired: true,
		},
		{
			name:    "invalid date format",
			rule:    Rule{ID: "CVE-2021-44228", Until: "invalid"},
			want:    true,
			expired: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.rule.IsExpired(); got != tt.expired {
				t.Errorf("Rule.IsExpired() = %v, want %v", got, tt.expired)
			}
			if got := tt.rule.Matches("CVE-2021-44228", "log4j", "maven"); got != tt.want {
				t.Errorf("Rule.Matches() = %v, want %v (expired rule should not match)", got, tt.want)
			}
		})
	}
}

func TestRulesShouldIgnore(t *testing.T) {
	rules := NewRules()
	rules.Add(
		Rule{ID: "CVE-2021-44228"},
		Rule{Package: "lodash"},
		Rule{Ecosystem: "deprecated"},
	)

	tests := []struct {
		name      string
		vulnID    string
		pkgName   string
		ecosystem string
		want      bool
	}{
		{"matches id", "CVE-2021-44228", "anything", "npm", true},
		{"matches package", "GHSA-xxxx", "lodash", "npm", true},
		{"matches ecosystem", "GHSA-xxxx", "some-pkg", "deprecated", true},
		{"no match", "GHSA-xxxx", "react", "npm", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rules.ShouldIgnore(tt.vulnID, tt.pkgName, tt.ecosystem)
			if got != tt.want {
				t.Errorf("Rules.ShouldIgnore() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLoadFromBytes(t *testing.T) {
	tests := []struct {
		name      string
		yaml      string
		wantCount int
	}{
		{
			name: "standalone ignore file",
			yaml: `
ignore:
  - id: CVE-2021-44228
    reason: Not exploitable in our environment
  - package: lodash
    until: "2025-12-31"
`,
			wantCount: 2,
		},
		{
			name: "embedded in config",
			yaml: `
logging:
  level: info
ignore:
  - id: CVE-2021-44228
`,
			wantCount: 1,
		},
		{
			name:      "empty file",
			yaml:      "",
			wantCount: 0,
		},
		{
			name: "no ignore section",
			yaml: `
logging:
  level: info
`,
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules, err := LoadFromBytes([]byte(tt.yaml))
			if err != nil {
				t.Fatalf("LoadFromBytes() error = %v", err)
			}
			if rules.Count() != tt.wantCount {
				t.Errorf("LoadFromBytes() count = %d, want %d", rules.Count(), tt.wantCount)
			}
		})
	}
}

func TestMatchingRule(t *testing.T) {
	rules := NewRules()
	rules.Add(
		Rule{ID: "CVE-2021-44228", Reason: "Known issue"},
		Rule{Package: "lodash", Reason: "Deprecated package"},
	)

	// Match by ID
	rule := rules.MatchingRule("CVE-2021-44228", "log4j", "maven")
	if rule == nil {
		t.Fatal("expected to find matching rule")
	}
	if rule.Reason != "Known issue" {
		t.Errorf("got reason %q, want %q", rule.Reason, "Known issue")
	}

	// Match by package
	rule = rules.MatchingRule("GHSA-xxxx", "lodash", "npm")
	if rule == nil {
		t.Fatal("expected to find matching rule")
	}
	if rule.Reason != "Deprecated package" {
		t.Errorf("got reason %q, want %q", rule.Reason, "Deprecated package")
	}

	// No match
	rule = rules.MatchingRule("GHSA-xxxx", "react", "npm")
	if rule != nil {
		t.Error("expected no matching rule")
	}
}

func TestActiveCount(t *testing.T) {
	yesterday := time.Now().AddDate(0, 0, -1).Format("2006-01-02")
	tomorrow := time.Now().AddDate(0, 0, 1).Format("2006-01-02")

	rules := NewRules()
	rules.Add(
		Rule{ID: "CVE-1"},                  // active
		Rule{ID: "CVE-2", Until: tomorrow}, // active
		Rule{ID: "CVE-3", Until: yesterday}, // expired
	)

	if rules.Count() != 3 {
		t.Errorf("Count() = %d, want 3", rules.Count())
	}
	if rules.ActiveCount() != 2 {
		t.Errorf("ActiveCount() = %d, want 2", rules.ActiveCount())
	}
}

func TestBaselineToRules(t *testing.T) {
	baseline := &Baseline{
		Version: "1",
		Created: time.Date(2024, 1, 15, 0, 0, 0, 0, time.UTC),
		Findings: []BaselineFinding{
			{ID: "CVE-2021-44228", Package: "log4j", Ecosystem: "maven"},
			{ID: "GHSA-xxxx", Package: "lodash", Ecosystem: "npm"},
		},
	}

	rules := baseline.ToRules()
	if rules.Count() != 2 {
		t.Errorf("ToRules() count = %d, want 2", rules.Count())
	}

	if !rules.ShouldIgnore("CVE-2021-44228", "log4j", "maven") {
		t.Error("baseline rule should match")
	}
}
