package releases

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	depssemver "deps.dev/util/semver"
)

// ErrNoMatch reports that no release matched the requested version selector.
var ErrNoMatch = errors.New("no matching release")

// Release is a version published by an upstream release source.
type Release struct {
	Version string
	Stable  bool
	// Channel is an optional upstream channel marker such as "lts".
	Channel string
}

// SelectOptions controls release version selection.
type SelectOptions struct {
	// Prefix is a fuzzy version request such as "1", "1.24", or "latest".
	Prefix string
	// SemverSystem controls ordering. If unset, DefaultSystem is used.
	SemverSystem depssemver.System
	// StripPrefixes are removed from both candidate versions and Prefix before
	// matching and returning. This is useful for upstreams that publish "v1.2.3"
	// or "go1.2.3" while the consuming manager wants "1.2.3".
	StripPrefixes []string
	// Channel restricts selection to releases marked with that channel. Channel
	// matching is case-insensitive.
	Channel string
}

// Newest returns the newest stable concrete release matching opts.Prefix.
func Newest(list []Release, opts SelectOptions) (string, error) {
	sys := opts.SemverSystem
	prefix := normalizeVersion(opts.Prefix, opts.StripPrefixes)
	var best string
	for _, release := range list {
		if !release.Stable {
			continue
		}
		if opts.Channel != "" && !strings.EqualFold(release.Channel, opts.Channel) {
			continue
		}
		version := normalizeVersion(release.Version, opts.StripPrefixes)
		if !isConcreteVersion(version) || isPrerelease(version) || !matchesPrefix(version, prefix) {
			continue
		}
		if best == "" || sys.Compare(version, best) > 0 {
			best = version
		}
	}
	if best == "" {
		if prefix == "" {
			return "", fmt.Errorf("%w: no stable versions found", ErrNoMatch)
		}
		return "", fmt.Errorf("%w: no stable version matching %q found", ErrNoMatch, prefix)
	}
	return best, nil
}

// normalizeVersion trims whitespace and repeatedly removes configured leading
// prefixes from a version string.
func normalizeVersion(version string, stripPrefixes []string) string {
	version = strings.TrimSpace(version)
	for {
		trimmed := version
		for _, prefix := range stripPrefixes {
			if prefix != "" {
				trimmed = strings.TrimPrefix(trimmed, prefix)
			}
		}
		if trimmed == version {
			return version
		}
		version = trimmed
	}
}

// concreteVersionRe accepts release streams whose final published tags may only
// contain major.minor.
var concreteVersionRe = regexp.MustCompile(`\d+\.\d+`)

// isConcreteVersion reports whether version is specific enough to be a resolved
// release candidate.
func isConcreteVersion(version string) bool {
	version = strings.TrimSpace(version)
	if version == "" {
		return false
	}
	if strings.ContainsAny(version, "^~*<>= ") || strings.Contains(version, "..") {
		return false
	}
	return concreteVersionRe.MatchString(version)
}

// prereleaseMarkerRe matches common prerelease qualifiers, including forms
// glued directly to the version core with no "." or "-" separator (e.g.
// "1.8.2rc1", "1.6rc2", "1.7rc1") that the older dot-only checks missed.
// Markers are unambiguous words that do not occur in stable version strings.
var prereleaseMarkerRe = regexp.MustCompile(`(?i)(alpha|beta|rc|snapshot|nightly|preview|milestone|pre)`)

// isPrerelease recognizes common prerelease markers across semver-like release
// streams. Build metadata (everything after "+") is ignored, since it can carry
// unrelated tokens (e.g. Java's "21.0.11+10.0.LTS").
func isPrerelease(version string) bool {
	v := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(version), "v"))
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	if strings.Contains(v, "-") {
		return true
	}
	return prereleaseMarkerRe.MatchString(v)
}

// matchesPrefix reports whether version satisfies a mise-style fuzzy prefix.
func matchesPrefix(version, prefix string) bool {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" || strings.EqualFold(prefix, "latest") {
		return true
	}
	v := strings.TrimPrefix(strings.TrimSpace(version), "v")
	p := strings.TrimPrefix(prefix, "v")
	return v == p ||
		strings.HasPrefix(v, p+".") ||
		strings.HasPrefix(v, p+"-")
}
