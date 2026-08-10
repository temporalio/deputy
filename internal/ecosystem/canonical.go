package ecosystem

import (
	"slices"
	"strings"
)

// Canonical tokens for ecosystems Deputy inventories or proxies but does not
// carry a full [Registration] for. They are part of the canonical policy
// vocabulary (see [Canonical]) even though [Default] has no capability entry
// for them, so [Default].Get returns nil for these values.
const (
	// GitHubActions identifies workflow action references (.github/workflows).
	// The inventory and OSV display form is "GitHub Actions".
	GitHubActions Ecosystem = "github-actions"

	// Docker identifies Dockerfile base images.
	Docker Ecosystem = "docker"

	// OCI identifies OCI registry artifacts served through the proxy.
	OCI Ecosystem = "oci"
)

// extraCanonicalAliases maps aliases for the ecosystems that have a canonical
// token but no [Registration], so [Parse] cannot resolve them. Keys are already
// normalized by [normalizeToken].
var extraCanonicalAliases = map[string]Ecosystem{
	"github-actions": GitHubActions,
	"githubactions":  GitHubActions,
	"github-action":  GitHubActions,
	"githubaction":   GitHubActions,
	"github":         GitHubActions,
	"actions":        GitHubActions,
	"gha":            GitHubActions,
	"docker":         Docker,
	"dockerfile":     Docker,
	"containerfile":  Docker,
	"container":      Docker,
	"oci":            OCI,
}

// extraCanonicalEcosystems lists the canonical tokens that have no
// [Registration], in the order they extend the registry's own tokens.
var extraCanonicalEcosystems = []Ecosystem{Docker, GitHubActions, OCI}

// Canonical resolves raw into the single spelling of an ecosystem that Deputy
// compares against: a lowercase, hyphenated token such as "go", "npm", "pypi",
// or "github-actions". It is the contract every policy sees; display forms
// ("Go", "PyPI", "GitHub Actions") exist only for rendering.
//
// known reports whether raw resolved to an ecosystem Deputy recognizes, either
// through the capability [Registry] (via [Parse] and its aliases) or through the
// registry-less tokens above. When known is false the returned token is still
// normalized (lowercased, whitespace and underscores folded to hyphens) so that
// unrecognized values such as OS package ecosystems ("Alpine:v3.19" ->
// "alpine:v3.19") still compare consistently instead of leaking scanner casing.
// Callers that must preserve the scanner's original spelling should check known
// and fall back to raw.
func Canonical(raw string) (token string, known bool) {
	// Parse sees the raw string first: some of its aliases carry separators of
	// their own ("cargo (crates.io)") that normalizeToken would fold away.
	if eco := Parse(raw); eco != Unknown {
		return string(eco), true
	}
	normalized := normalizeToken(raw)
	if normalized == "" {
		return "", false
	}
	if eco, ok := extraCanonicalAliases[normalized]; ok {
		return string(eco), true
	}
	if eco := Parse(normalized); eco != Unknown {
		return string(eco), true
	}
	return normalized, false
}

// CanonicalOrRaw returns the canonical token for raw, falling back to the
// normalized token for values Deputy does not recognize. It is the convenience
// form of [Canonical] for callers that always want a comparable value.
func CanonicalOrRaw(raw string) string {
	token, _ := Canonical(raw)
	return token
}

// IsCanonical reports whether raw names an ecosystem Deputy recognizes. It is
// the acceptance test for author-supplied ecosystem names (for example a policy
// bundle's "ecosystems:" key) and is case- and alias-insensitive: "Go",
// "golang", and "go" all report true.
func IsCanonical(raw string) bool {
	_, known := Canonical(raw)
	return known
}

// CanonicalEcosystems returns every canonical ecosystem token, sorted, so
// callers can report the valid set in a validation error or completion list.
func CanonicalEcosystems() []string {
	registered := Default().Ecosystems()
	out := make([]string, 0, len(registered)+len(extraCanonicalEcosystems))
	for _, eco := range registered {
		out = append(out, string(eco))
	}
	for _, eco := range extraCanonicalEcosystems {
		out = append(out, string(eco))
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// normalizeToken lowercases raw and folds the separators ecosystem names arrive
// with (spaces from display forms, underscores from flags and JSON) into the
// hyphen that canonical tokens use.
func normalizeToken(raw string) string {
	token := strings.ToLower(strings.TrimSpace(raw))
	if token == "" {
		return ""
	}
	token = strings.ReplaceAll(token, "_", "-")
	// Collapse internal whitespace runs so "GitHub  Actions" and "Red Hat"
	// normalize the same way regardless of how the source spaced them.
	token = strings.Join(strings.Fields(token), "-")
	return token
}
