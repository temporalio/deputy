package osv

import (
	"encoding/json"
	"regexp"
	"slices"
	"strings"
)

// IsNotFoundError reports whether an error from the OSV client represents a
// missing vulnerability ID. The upstream client currently returns formatted
// HTTP response text instead of a structured status error.
func IsNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	if strings.Contains(msg, `status="404`) {
		return true
	}
	return strings.Contains(msg, `"code":5`) && strings.Contains(strings.ToLower(msg), "not found")
}

// osvErrorBodyMarker precedes the response body inside the osv.dev client's
// formatted error text ("client error: status=%q body=%s").
const osvErrorBodyMarker = "body="

// advisoryIDPattern matches an OSV advisory identifier: an uppercase database
// prefix followed by dash-separated alphanumeric segments, as in CVE-2026-61711,
// GHSA-7236-3392-c5c6, or GO-2026-6255. Matching on shape rather than on a list
// of known prefixes means a database Deputy has never heard of still matches,
// and keeps this from becoming another list to maintain.
var advisoryIDPattern = regexp.MustCompile(`\b[A-Z][A-Z0-9]*(?:-[A-Za-z0-9]+)+\b`)

// NotFoundAliases returns the advisory IDs an OSV not-found response names as
// records that do exist. When a record is withdrawn, renamed, or merged, OSV
// answers a lookup for it with "Vulnerability not found, but the following
// aliases were: CVE-... GHSA-...", and that response is the only place those
// IDs appear: the querybatch stub that named the missing ID carries just an id
// and a modified timestamp.
//
// The upstream client renders the response as formatted text rather than a
// typed status, so these IDs are read back out of the error string. They are
// therefore a hint and not a contract: a caller must confirm that a record
// fetched for a returned ID actually affects the package it was asking about,
// and must treat an empty result as "no recovery available" rather than as an
// error. IDs come back in the order OSV listed them, deduplicated
// case-insensitively.
func NotFoundAliases(err error) []string {
	if !IsNotFoundError(err) {
		return nil
	}
	text := err.Error()
	// Prefer the decoded body message. Falling back to the whole error string
	// costs nothing: the surrounding text ("client error", "404 Not Found")
	// holds no advisory-shaped tokens.
	if idx := strings.LastIndex(text, osvErrorBodyMarker); idx >= 0 {
		var body struct {
			Message string `json:"message"`
		}
		if err := json.Unmarshal([]byte(text[idx+len(osvErrorBodyMarker):]), &body); err == nil && body.Message != "" {
			text = body.Message
		}
	}

	var out []string
	for _, candidate := range advisoryIDPattern.FindAllString(text, -1) {
		// Every OSV database numbers its records, so a token without a digit is
		// prose that happens to be hyphenated, not an identifier.
		if !strings.ContainsAny(candidate, "0123456789") {
			continue
		}
		if slices.ContainsFunc(out, func(existing string) bool {
			return strings.EqualFold(existing, candidate)
		}) {
			continue
		}
		out = append(out, candidate)
	}
	return out
}
