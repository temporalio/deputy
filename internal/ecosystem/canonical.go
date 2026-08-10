package ecosystem

import (
	"slices"
	"strings"

	packageurl "github.com/package-url/packageurl-go"

	"github.com/temporalio/deputy/internal/purlx"
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

	// Hackage identifies Haskell packages. OSV-SCALIBR inventories them from
	// cabal and stack files and reports them as "Hackage".
	Hackage Ecosystem = "hackage"

	// CRAN identifies R packages. OSV-SCALIBR inventories them from renv and
	// reports them as "CRAN".
	CRAN Ecosystem = "cran"

	// ConanCenter identifies C and C++ packages. OSV-SCALIBR inventories them
	// from conan files and reports them as "ConanCenter".
	ConanCenter Ecosystem = "conancenter"
)

// extraCanonicalEcosystems describes the ecosystems that have a canonical token
// but no capability [Registration]. Deputy identifies packages in all three but
// resolves their capabilities elsewhere (a Deputy extractor plugin for
// Dockerfiles and workflows, a proxy handler for OCI), so they are not in the
// registry. Keeping their token, display name, and aliases here means no
// surface has to spell them out for itself.
var extraCanonicalEcosystems = []Registration{
	{
		Ecosystem:   Docker,
		DisplayName: "docker",
		Description: "Dockerfile base images",
		Aliases:     []string{"dockerfile", "containerfile", "container"},
		PURLType:    packageurl.TypeDocker,
	},
	{
		Ecosystem:   GitHubActions,
		DisplayName: "GitHub Actions",
		Description: "Workflow action references (.github/workflows)",
		Aliases:     []string{"githubactions", "github-action", "githubaction", "github", "actions", "gha"},
		PURLType:    purlx.TypeGitHubActions,
	},
	{
		Ecosystem:   OCI,
		DisplayName: "oci",
		Description: "OCI registry artifacts served through the proxy",
		Aliases:     []string{},
		PURLType:    packageurl.TypeOCI,
	},
	{
		Ecosystem:   Hackage,
		DisplayName: "Hackage",
		Description: "Haskell packages, inventoried through OSV-SCALIBR (cabal, stack)",
		Aliases:     []string{"haskell", "cabal", "stack"},
		PURLType:    packageurl.TypeHackage,
	},
	{
		Ecosystem:   CRAN,
		DisplayName: "CRAN",
		Description: "R packages, inventoried through OSV-SCALIBR (renv)",
		Aliases:     []string{"r", "renv"},
		PURLType:    packageurl.TypeCran,
	},
	{
		Ecosystem:   ConanCenter,
		DisplayName: "ConanCenter",
		Description: "C/C++ packages, inventoried through OSV-SCALIBR (conan)",
		Aliases:     []string{"cpp", "c++", "conan"},
		PURLType:    packageurl.TypeConan,
	},
}

// extraCanonicalAliases indexes [extraCanonicalEcosystems] by every spelling
// that resolves to it, including its own token and display name. Keys are
// normalized by [normalizeToken].
var extraCanonicalAliases = func() map[string]Ecosystem {
	out := make(map[string]Ecosystem)
	for _, reg := range extraCanonicalEcosystems {
		out[normalizeToken(string(reg.Ecosystem))] = reg.Ecosystem
		out[normalizeToken(reg.DisplayName)] = reg.Ecosystem
		for _, alias := range reg.Aliases {
			out[normalizeToken(alias)] = reg.Ecosystem
		}
	}
	return out
}()

// Display returns the human-readable name for an ecosystem: the registry's
// DisplayName, or the display name of a token that has no [Registration]. It is
// the only source of those strings, so a surface that renders an ecosystem
// never has to hardcode one. Unknown ecosystems render as their own token.
func Display(eco Ecosystem) string {
	if reg := Default().Get(eco); reg != nil && reg.DisplayName != "" {
		return reg.DisplayName
	}
	for _, reg := range extraCanonicalEcosystems {
		if reg.Ecosystem == eco {
			return reg.DisplayName
		}
	}
	return string(eco)
}

// PURLType returns the package-url type that identifies eco inside a PURL. It
// is the registry's [ProjectionPURLType], for both the ecosystems [Default]
// carries and the registry-less canonical tokens, so no surface has to keep its
// own ecosystem-to-purl-type switch. The type is often not the canonical token
// ("go" is pkg:golang, "conancenter" is pkg:conan), which is exactly why
// guessing it from the token produces PURLs that do not route. Ecosystems
// Deputy does not know return "".
func PURLType(eco Ecosystem) string {
	if reg := Default().Get(eco); reg != nil && reg.PURLType != "" {
		return reg.PURLType
	}
	for _, reg := range extraCanonicalEcosystems {
		if reg.Ecosystem == eco {
			return reg.PURLType
		}
	}
	return ""
}

// Canonical resolves raw into the single spelling of an ecosystem that Deputy
// compares against: a lowercase, hyphenated token such as "go", "npm", "pypi",
// or "github-actions". It is the contract every policy sees; display forms
// ("Go", "PyPI", "GitHub Actions") exist only for rendering.
//
// known reports whether raw resolved to an ecosystem Deputy recognizes: one
// [Parse] knows, one of the registry-less tokens above, or one registered into
// the runtime [Registry], so an ecosystem contributed at runtime is understood
// everywhere without a second table. When known is false the returned token is still
// normalized (lowercased, whitespace and underscores folded to hyphens) so that
// unrecognized values such as OS package ecosystems ("Alpine:v3.19" ->
// "alpine:v3.19") still compare consistently instead of leaking scanner casing.
// Callers that must preserve the scanner's original spelling should check known
// and fall back to raw.
func Canonical(raw string) (token string, known bool) {
	return canonicalIn(Default(), raw)
}

// canonicalIn resolves raw against a specific registry. [Canonical] uses the
// default one; tests use their own so a registration cannot leak between them.
func canonicalIn(registry *Registry, raw string) (token string, known bool) {
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
	// Anything in the registry resolves from the registry, so an ecosystem
	// added there is as nameable as a built-in one without a second table.
	//
	// Nothing in production adds one yet: an extractor plugin's ecosystem is
	// stored in the inventory plugin registry and never reaches this one, so a
	// plugin that inventories "custom-ecosystem" can scan packages while a
	// policy naming that ecosystem still fails to load. Wiring the two together
	// is not a one-liner, because [Registry.Register] overwrites an existing
	// registration and the only caller of the inventory registry is an RPC
	// handler, which would let a remote registration shadow a built-in
	// ecosystem's upstream URL. Tracked in
	// https://github.com/temporalio/deputy/issues/185.
	if reg := registry.Get(Ecosystem(normalized)); reg != nil {
		return string(reg.Ecosystem), true
	}
	if reg := registry.Lookup(normalized); reg != nil {
		return string(reg.Ecosystem), true
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
	for _, reg := range extraCanonicalEcosystems {
		out = append(out, string(reg.Ecosystem))
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
