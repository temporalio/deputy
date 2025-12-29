package flags

import (
	"fmt"
	"io"
	"time"

	analysis "github.com/picatz/deputy/internal/analysis"
)

// ParsePublishedFilters parses the date filter flags and returns the before and after times.
func ParsePublishedFilters(errW io.Writer, asOfStr, beforeStr, afterStr string) (time.Time, time.Time) {
	var beforeT, afterT time.Time
	if asOfStr != "" {
		if t, err := analysis.ParseFlexibleDate(asOfStr, "asof"); err == nil {
			beforeT = t
		} else {
			fmt.Fprintf(errW, "Warning: could not parse --as-of date %q: %v\n", asOfStr, err)
		}
	}
	if beforeStr != "" && beforeT.IsZero() {
		if t, err := analysis.ParseFlexibleDate(beforeStr, "before"); err == nil {
			beforeT = t
		} else {
			fmt.Fprintf(errW, "Warning: could not parse --published-before %q: %v\n", beforeStr, err)
		}
	}
	if afterStr != "" {
		if t, err := analysis.ParseFlexibleDate(afterStr, "after"); err == nil {
			afterT = t
		} else {
			fmt.Fprintf(errW, "Warning: could not parse --published-after %q: %v\n", afterStr, err)
		}
	}
	return beforeT, afterT
}
