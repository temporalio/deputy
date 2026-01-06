// Package ignore provides vulnerability ignore/baseline functionality.
//
// Deputy supports ignoring vulnerabilities through multiple mechanisms:
//
//   - Configuration file (.deputy.yaml): Add ignore rules under the "ignore" key
//   - Dedicated ignore file (.deputyignore.yaml): A standalone file with ignore rules
//   - Baseline file (deputy-baseline.yaml): A snapshot of known issues to suppress
//
// # Ignore Rule Matching
//
// Ignore rules can match vulnerabilities by:
//
//   - id: Exact vulnerability ID (e.g., "CVE-2021-44228", "GHSA-xxxx-xxxx-xxxx")
//   - package: Package name pattern (e.g., "lodash", "github.com/user/*")
//   - ecosystem: Ecosystem name (e.g., "go", "npm")
//
// All non-empty conditions in a rule must match for the vulnerability to be ignored.
//
// # Rule Expiration
//
// Rules can have an expiration date using the "until" field. Expired rules
// are ignored during evaluation, allowing temporary acknowledgments with
// automatic re-surfacing.
//
// # Usage
//
//	rules, err := ignore.LoadFromPath(".deputy.yaml")
//	if err != nil {
//	    // handle error
//	}
//
//	if rules.ShouldIgnore(finding.AdvisoryID, pkg.Name, pkg.Ecosystem) {
//	    // skip this finding
//	}
package ignore

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Rule defines a single ignore rule for vulnerabilities.
type Rule struct {
	// ID matches a specific vulnerability ID (CVE, GHSA, etc.).
	// Exact match only.
	ID string `yaml:"id,omitempty" json:"id,omitempty"`

	// Package matches the package name. Supports trailing wildcards (e.g., "github.com/user/*").
	Package string `yaml:"package,omitempty" json:"package,omitempty"`

	// Ecosystem matches the package ecosystem (e.g., "go", "npm").
	Ecosystem string `yaml:"ecosystem,omitempty" json:"ecosystem,omitempty"`

	// Reason documents why this vulnerability is being ignored.
	// This is optional but highly recommended for audit trails.
	Reason string `yaml:"reason,omitempty" json:"reason,omitempty"`

	// Until sets an expiration date for this rule (YYYY-MM-DD format).
	// After this date, the rule no longer applies.
	Until string `yaml:"until,omitempty" json:"until,omitempty"`

	// Author identifies who created this rule (optional).
	Author string `yaml:"author,omitempty" json:"author,omitempty"`

	// Created records when this rule was added (YYYY-MM-DD format, optional).
	Created string `yaml:"created,omitempty" json:"created,omitempty"`
}

// IsExpired returns true if the rule has an expiration date that has passed.
// The rule is considered valid through the entire specified day.
func (r Rule) IsExpired() bool {
	if r.Until == "" {
		return false
	}
	until, err := time.Parse("2006-01-02", r.Until)
	if err != nil {
		return false // Invalid date format, treat as not expired
	}
	// Expire at the end of the specified day (add 24 hours then check)
	endOfDay := until.Add(24 * time.Hour)
	return time.Now().After(endOfDay)
}

// Matches returns true if the rule matches the given vulnerability.
// All non-empty conditions must match.
func (r Rule) Matches(vulnID, pkgName, eco string) bool {
	if r.IsExpired() {
		return false
	}

	if r.ID != "" && !strings.EqualFold(r.ID, vulnID) {
		return false
	}

	if r.Package != "" && !matchPattern(r.Package, pkgName) {
		return false
	}

	if r.Ecosystem != "" && !strings.EqualFold(r.Ecosystem, eco) {
		return false
	}

	// At least one condition must be specified
	return r.ID != "" || r.Package != "" || r.Ecosystem != ""
}

// matchPattern matches a package name against a pattern.
// Supports trailing wildcards (e.g., "github.com/user/*").
func matchPattern(pattern, name string) bool {
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		return strings.HasPrefix(name, prefix+"/") || name == prefix
	}
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(name, prefix)
	}
	return strings.EqualFold(pattern, name)
}

// Rules is a collection of ignore rules.
type Rules struct {
	rules []Rule
}

// NewRules creates an empty Rules collection.
func NewRules() *Rules {
	return &Rules{}
}

// Add adds rules to the collection.
func (r *Rules) Add(rules ...Rule) {
	r.rules = append(r.rules, rules...)
}

// ShouldIgnore returns true if any rule matches the vulnerability.
func (r *Rules) ShouldIgnore(vulnID, pkgName, ecosystem string) bool {
	for _, rule := range r.rules {
		if rule.Matches(vulnID, pkgName, ecosystem) {
			return true
		}
	}
	return false
}

// MatchingRule returns the first rule that matches the vulnerability, or nil.
func (r *Rules) MatchingRule(vulnID, pkgName, ecosystem string) *Rule {
	for i := range r.rules {
		if r.rules[i].Matches(vulnID, pkgName, ecosystem) {
			return &r.rules[i]
		}
	}
	return nil
}

// All returns all rules.
func (r *Rules) All() []Rule {
	return r.rules
}

// Count returns the number of rules.
func (r *Rules) Count() int {
	return len(r.rules)
}

// ActiveCount returns the number of non-expired rules.
func (r *Rules) ActiveCount() int {
	count := 0
	for _, rule := range r.rules {
		if !rule.IsExpired() {
			count++
		}
	}
	return count
}

// ignoreFile represents the YAML structure for standalone ignore files.
type ignoreFile struct {
	Ignore []Rule `yaml:"ignore"`
}

// configFile represents the structure when embedded in .deputy.yaml.
type configFile struct {
	Ignore []Rule `yaml:"ignore,omitempty"`
}

// LoadFromPath loads ignore rules from a file.
// It accepts .deputy.yaml (extracts "ignore" key) or a dedicated ignore file.
func LoadFromPath(path string) (*Rules, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return LoadFromBytes(data)
}

// LoadFromBytes loads ignore rules from YAML bytes.
func LoadFromBytes(data []byte) (*Rules, error) {
	rules := NewRules()

	// Try as standalone ignore file first
	var ignoreDoc ignoreFile
	if err := yaml.Unmarshal(data, &ignoreDoc); err == nil && len(ignoreDoc.Ignore) > 0 {
		rules.Add(ignoreDoc.Ignore...)
		return rules, nil
	}

	// Try as config file with embedded ignore
	var configDoc configFile
	if err := yaml.Unmarshal(data, &configDoc); err == nil && len(configDoc.Ignore) > 0 {
		rules.Add(configDoc.Ignore...)
		return rules, nil
	}

	return rules, nil
}

// LoadFromDirectory searches for ignore files in a directory.
// It looks for: .deputy.yaml, .deputyignore.yaml, deputy-baseline.yaml
func LoadFromDirectory(dir string) (*Rules, error) {
	rules := NewRules()

	candidates := []string{
		".deputy.yaml",
		".deputyignore.yaml",
		"deputy-baseline.yaml",
	}

	for _, name := range candidates {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err != nil {
			continue
		}
		fileRules, err := LoadFromPath(path)
		if err != nil {
			return nil, err
		}
		rules.Add(fileRules.All()...)
	}

	return rules, nil
}

// Baseline represents a snapshot of vulnerabilities at a point in time.
type Baseline struct {
	// Version is the baseline format version.
	Version string `yaml:"version" json:"version"`

	// Created is when the baseline was generated.
	Created time.Time `yaml:"created" json:"created"`

	// Description provides context about this baseline.
	Description string `yaml:"description,omitempty" json:"description,omitempty"`

	// Findings are the vulnerabilities captured in this baseline.
	Findings []BaselineFinding `yaml:"findings" json:"findings"`
}

// BaselineFinding captures a vulnerability in the baseline.
type BaselineFinding struct {
	// ID is the vulnerability ID.
	ID string `yaml:"id" json:"id"`

	// Package is the affected package name.
	Package string `yaml:"package" json:"package"`

	// Version is the affected package version.
	Version string `yaml:"version,omitempty" json:"version,omitempty"`

	// Ecosystem is the package ecosystem.
	Ecosystem string `yaml:"ecosystem" json:"ecosystem"`

	// Severity is the vulnerability severity (for informational purposes).
	Severity string `yaml:"severity,omitempty" json:"severity,omitempty"`

	// FirstSeen is when this vulnerability was first added to the baseline.
	FirstSeen time.Time `yaml:"first_seen,omitempty" json:"first_seen,omitempty"`
}

// ToRules converts a baseline to ignore rules.
func (b *Baseline) ToRules() *Rules {
	rules := NewRules()
	for _, f := range b.Findings {
		rules.Add(Rule{
			ID:        f.ID,
			Package:   f.Package,
			Ecosystem: f.Ecosystem,
			Reason:    "In baseline (captured " + b.Created.Format("2006-01-02") + ")",
		})
	}
	return rules
}

// SaveBaseline writes a baseline to a file.
func SaveBaseline(path string, baseline *Baseline) error {
	data, err := yaml.Marshal(baseline)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// LoadBaseline loads a baseline from a file.
func LoadBaseline(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var baseline Baseline
	if err := yaml.Unmarshal(data, &baseline); err != nil {
		return nil, err
	}
	return &baseline, nil
}
