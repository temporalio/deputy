package scan

import (
	"time"

	vulnerabilityv1 "github.com/picatz/deputy/gen/deputy/vulnerability/v1"
	"github.com/picatz/deputy/internal/vulnerability"
)

// filterFindingsByPublished filters findings based on the advisory's published timestamp.
func filterFindingsByPublished(findings []vulnerability.Finding, advisories map[string]vulnerabilityv1.Advisory, after, before time.Time) []vulnerability.Finding {
	if after.IsZero() && before.IsZero() {
		return findings
	}
	out := make([]vulnerability.Finding, 0, len(findings))
	for _, f := range findings {
		adv, ok := advisories[f.AdvisoryID]
		if !ok {
			// No advisory - can't filter, include if no 'after' constraint
			if after.IsZero() {
				out = append(out, f)
			}
			continue
		}
		pt := vulnerability.AdvisoryPublished(&adv)
		if pt.IsZero() {
			if after.IsZero() {
				out = append(out, f)
			}
			continue
		}
		if !after.IsZero() && pt.Before(after) {
			continue
		}
		if !before.IsZero() && pt.After(before) {
			continue
		}
		out = append(out, f)
	}
	return out
}
