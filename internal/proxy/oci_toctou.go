// Package proxy provides HTTP proxy handlers for package ecosystems.
//
// This file implements TOCTOU (Time-Of-Check-To-Time-Of-Use) vulnerability
// mitigation for the OCI registry proxy. The core problem is that mutable
// tags like :latest can change between policy evaluation and upstream fetch.
//
// The solution uses digest pinning: when a request uses a mutable tag,
// the proxy resolves it to an immutable digest during policy evaluation,
// then rewrites the upstream request to use that digest. This ensures
// the content fetched matches what was scanned.
//
// See CWE-367 for background: https://cwe.mitre.org/data/definitions/367.html
package proxy

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"strings"
)

// Response headers for TOCTOU mitigation auditability.
const (
	// HeaderPinnedDigest contains the digest that was pinned during policy evaluation.
	// Clients can use this to verify the content they receive matches what was scanned.
	HeaderPinnedDigest = "X-Deputy-Pinned-Digest"

	// HeaderDigestPinningEnabled indicates whether digest pinning is active.
	HeaderDigestPinningEnabled = "X-Deputy-Digest-Pinning"

	// HeaderMutableTagBlocked indicates a request was blocked due to mutable tag policy.
	HeaderMutableTagBlocked = "X-Deputy-Mutable-Tag-Blocked"
)

// isMutableTag returns true if the given tag is considered mutable.
// Mutable tags are those that can change over time, unlike digests.
// Common examples: latest, stable, edge, nightly, dev, snapshot.
func isMutableTag(tag string) bool {
	if tag == "" {
		return false
	}
	// Digests are immutable
	if strings.HasPrefix(tag, "sha256:") || strings.HasPrefix(tag, "sha512:") {
		return false
	}

	// Explicitly mutable tags
	mutableTags := map[string]bool{
		"latest":   true,
		"stable":   true,
		"edge":     true,
		"nightly":  true,
		"dev":      true,
		"snapshot": true,
		"master":   true,
		"main":     true,
	}
	if mutableTags[strings.ToLower(tag)] {
		return true
	}

	// Tags with only digits are likely date-based or build numbers (mutable)
	// e.g., "20240101", "12345"
	allDigits := true
	for _, r := range tag {
		if r < '0' || r > '9' {
			allDigits = false
			break
		}
	}
	if allDigits && len(tag) > 0 {
		return true
	}

	// Semver-like tags (v1.2.3, 1.2.3) are considered immutable
	// because they typically point to a specific release
	if looksLikeSemver(tag) {
		return false
	}

	// Default: treat non-semver tags as mutable (conservative approach)
	// This includes tags like "alpine", "bookworm", "bullseye", etc.
	return true
}

// looksLikeSemver returns true if the tag appears to be a semantic version.
func looksLikeSemver(tag string) bool {
	// Strip leading 'v' if present
	s := strings.TrimPrefix(tag, "v")
	if s == "" {
		return false
	}

	// Must contain at least one dot
	if !strings.Contains(s, ".") {
		return false
	}

	// Split by dots and check each part is numeric
	parts := strings.Split(s, ".")
	for _, part := range parts {
		// Allow trailing metadata (e.g., 1.2.3-alpine, 1.2.3+build)
		subpart, _, _ := strings.Cut(part, "-")
		subpart, _, _ = strings.Cut(subpart, "+")
		if subpart == "" {
			continue
		}
		for _, r := range subpart {
			if r < '0' || r > '9' {
				return false
			}
		}
	}

	return len(parts) >= 2
}

// digestPinningProxy wraps the upstream proxy to rewrite manifest requests
// using the pinned digest instead of the mutable tag.
type digestPinningProxy struct {
	upstream   *httputil.ReverseProxy
	registry   string
	ociConfig  *OCIConfig
	pinnedInfo *pinnedRequestInfo
}

// pinnedRequestInfo holds the pinned digest and rewrite information.
type pinnedRequestInfo struct {
	OriginalTag  string
	PinnedDigest string
	Repository   string
}

// newDigestPinningProxy creates a proxy that rewrites requests to use pinned digests.
func newDigestPinningProxy(upstream *httputil.ReverseProxy, registry string, cfg *OCIConfig) *digestPinningProxy {
	return &digestPinningProxy{
		upstream:  upstream,
		registry:  registry,
		ociConfig: cfg,
	}
}

// withPinnedInfo returns a copy with the pinned request info set.
func (p *digestPinningProxy) withPinnedInfo(info *pinnedRequestInfo) *digestPinningProxy {
	return &digestPinningProxy{
		upstream:   p.upstream,
		registry:   p.registry,
		ociConfig:  p.ociConfig,
		pinnedInfo: info,
	}
}

func (p *digestPinningProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Add audit headers
	if p.ociConfig.EffectivePinDigests() {
		w.Header().Set(HeaderDigestPinningEnabled, "true")
	}

	// If we have pinned info, rewrite the request path
	if p.pinnedInfo != nil && p.pinnedInfo.PinnedDigest != "" {
		// Add the pinned digest header for auditability
		w.Header().Set(HeaderPinnedDigest, p.pinnedInfo.PinnedDigest)

		// Rewrite the URL path to use the digest instead of the tag
		originalPath := r.URL.Path
		newPath := rewriteManifestPath(originalPath, p.pinnedInfo.OriginalTag, p.pinnedInfo.PinnedDigest)
		if newPath != originalPath {
			// Clone the request to avoid modifying the original
			r2 := r.Clone(r.Context())
			r2.URL.Path = newPath
			r2.RequestURI = newPath
			if r.URL.RawQuery != "" {
				r2.RequestURI = newPath + "?" + r.URL.RawQuery
			}
			p.upstream.ServeHTTP(w, r2)
			return
		}
	}

	p.upstream.ServeHTTP(w, r)
}

// rewriteManifestPath rewrites a manifest path to use a digest instead of a tag.
// Example: /v2/library/nginx/manifests/latest -> /v2/library/nginx/manifests/sha256:abc...
func rewriteManifestPath(path, tag, digest string) string {
	if tag == "" || digest == "" {
		return path
	}

	// Find the manifests segment and replace the tag with digest
	suffix := "/manifests/" + tag
	if strings.HasSuffix(path, suffix) {
		return strings.TrimSuffix(path, suffix) + "/manifests/" + digest
	}

	return path
}

// mutableTagError is returned when a mutable tag is blocked by policy.
type mutableTagError struct {
	Tag        string
	Repository string
	Reason     string
}

func (e *mutableTagError) Error() string {
	return fmt.Sprintf("mutable tag %q for repository %q is not allowed: %s", e.Tag, e.Repository, e.Reason)
}

// checkMutableTagPolicy validates whether a mutable tag request is allowed.
// Returns an error if the request should be blocked.
func checkMutableTagPolicy(cfg *OCIConfig, tag, repository, digest string) error {
	if cfg == nil {
		return nil // No config, allow by default
	}

	// If it's not a mutable tag, allow it
	if !isMutableTag(tag) {
		return nil
	}

	// If mutable tags are allowed, permit the request
	if cfg.EffectiveAllowMutableTags() {
		return nil
	}

	// Mutable tags are not allowed, but digest pinning is enabled
	// and we successfully resolved the digest - this is the secure path
	if cfg.EffectivePinDigests() && digest != "" {
		return nil
	}

	// Mutable tag with no digest - block the request
	return &mutableTagError{
		Tag:        tag,
		Repository: repository,
		Reason:     "use digest reference or enable pin_digests for TOCTOU protection",
	}
}
