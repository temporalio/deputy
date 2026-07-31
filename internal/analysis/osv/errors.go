package osv

import (
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
