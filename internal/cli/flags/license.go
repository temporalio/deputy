package flags

import "strings"

const (
	LicenseSourceDepsDev = "depsdev"
	LicenseSourceScan    = "scan"
	LicenseSourceBoth    = "both"
)

// NormalizeLicenseSource lowercases and trims a license source value.
func NormalizeLicenseSource(source string) string {
	return strings.ToLower(strings.TrimSpace(source))
}

// IsLicenseSourceKnown reports whether the license source is recognized.
func IsLicenseSourceKnown(source string) bool {
	switch NormalizeLicenseSource(source) {
	case LicenseSourceDepsDev, LicenseSourceScan, LicenseSourceBoth:
		return true
	default:
		return false
	}
}
