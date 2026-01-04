// Package security provides shared security utilities for container analysis.
package security

import "strings"

// SensitiveEnvPatterns contains patterns that indicate potentially sensitive
// environment variable names. Used by both container image and Dockerfile analysis
// to detect secrets that should not be baked into images.
var SensitiveEnvPatterns = []string{
	"PASSWORD", "PASSWD", "PWD",
	"SECRET", "KEY", "TOKEN",
	"API_KEY", "APIKEY",
	"PRIVATE", "CREDENTIAL",
	"AUTH", "ACCESS_KEY",
	"AWS_SECRET", "GITHUB_TOKEN",
	"DATABASE_URL", "CONNECTION_STRING",
}

// DetectSensitiveEnvNames returns environment variable names that match
// sensitive patterns. Takes a map of name->value pairs (Dockerfile ENV format).
func DetectSensitiveEnvNames(envVars map[string]string) []string {
	var sensitive []string
	for name := range envVars {
		if IsSensitiveEnvName(name) {
			sensitive = append(sensitive, name)
		}
	}
	return sensitive
}

// DetectSensitiveEnvFromList returns environment variable names that match
// sensitive patterns. Takes a slice of KEY=VALUE strings (container config format).
func DetectSensitiveEnvFromList(envList []string) []string {
	var sensitive []string
	for _, env := range envList {
		name, _, _ := strings.Cut(env, "=")
		if IsSensitiveEnvName(name) {
			sensitive = append(sensitive, name)
		}
	}
	return sensitive
}

// IsSensitiveEnvName returns true if the given environment variable name
// matches any of the sensitive patterns.
func IsSensitiveEnvName(name string) bool {
	nameUpper := strings.ToUpper(name)
	for _, pattern := range SensitiveEnvPatterns {
		if strings.Contains(nameUpper, pattern) {
			return true
		}
	}
	return false
}
