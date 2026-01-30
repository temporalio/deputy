// Package terraform provides vulnerability mapping for Terraform packages.
//
// Since OSV doesn't have a native "Terraform" ecosystem, this package maps
// Terraform providers, core, and modules to their Go module paths for
// vulnerability queries via the Go ecosystem.
package terraform

import (
	"regexp"
	"strings"
)

// GoModulePath is the canonical Go module path for Terraform core.
const GoModulePath = "github.com/hashicorp/terraform"

// gitHubURLPattern matches git:: prefixed URLs and bare GitHub URLs.
var gitHubURLPattern = regexp.MustCompile(`^(?:git::)?(?:https?://)?(?:www\.)?github\.com/([^/?#]+)/([^/?#]+?)(?:\.git)?(?:\?.*)?$`)

// MapProviderToGoModule converts a Terraform provider source to its Go module path.
//
// Most providers follow: namespace/name -> github.com/namespace/terraform-provider-name
func MapProviderToGoModule(source string) string {
	namespace, name, ok := strings.Cut(strings.TrimSpace(source), "/")
	if !ok {
		return ""
	}
	namespace = strings.TrimSpace(namespace)
	name = strings.TrimSpace(name)
	if namespace == "" || name == "" {
		return ""
	}
	return "github.com/" + namespace + "/terraform-provider-" + name
}

// MapGitModuleToGoModule extracts the Go module path from a git module source.
// Only GitHub modules are supported.
func MapGitModuleToGoModule(source string) string {
	matches := gitHubURLPattern.FindStringSubmatch(strings.TrimSpace(source))
	if len(matches) < 3 {
		return ""
	}
	owner, repo := matches[1], strings.TrimSuffix(matches[2], ".git")
	return "github.com/" + owner + "/" + repo
}

// ExtractGitRef extracts the ref parameter from a git module source URL.
func ExtractGitRef(source string) string {
	_, after, found := strings.Cut(source, "?ref=")
	if !found {
		return ""
	}
	ref, _, _ := strings.Cut(after, "&")
	return strings.TrimSpace(ref)
}

// NormalizeGoVersion ensures a version string has the v prefix required by Go modules.
func NormalizeGoVersion(version string) string {
	v := strings.TrimSpace(version)
	if v == "" {
		return ""
	}
	if strings.HasPrefix(v, "v") {
		return v
	}
	return "v" + v
}
