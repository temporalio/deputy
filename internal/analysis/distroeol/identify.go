package distroeol

import (
	"regexp"
	"strings"

	packageurl "github.com/package-url/packageurl-go"
)

// Origins of an identification.
const (
	// OriginOSPackage is installed OS package metadata. The inventory copies
	// os-release into each package's distro qualifier, so this is the image's
	// own statement of what it runs.
	OriginOSPackage = "os-package"
	// OriginImageRef is a container image reference whose tag names a release,
	// such as a Dockerfile FROM line. It says what the build starts from, not
	// what was installed.
	OriginImageRef = "image-ref"
)

// Identity is a detected operating system release.
type Identity struct {
	// Distribution is the os-release ID, e.g. "alpine", or for OS packages of
	// an untracked distribution, the PURL namespace as found.
	Distribution string
	// Release is the normalized release: a cycle ("3.18", "12", "24.04"), a
	// codename ("bookworm"), or the raw value when it cannot be normalized.
	Release string
	// Version is the most specific version seen, e.g. "3.18.12".
	Version string
	// Origin is OriginOSPackage or OriginImageRef.
	Origin string
}

// osPackageTypes are the PURL types whose distro qualifier records os-release.
var osPackageTypes = map[string]bool{"apk": true, "deb": true, "rpm": true}

// FromOSPackage reads the release from an installed OS package's PURL, e.g.
// pkg:apk/alpine/musl@1.2.4-r2?distro=3.18.12 or
// pkg:deb/debian/libc6@2.36-9?distro=bookworm. It reports false for anything
// that is not an OS package or carries no distro qualifier.
func FromOSPackage(purl string) (Identity, bool) {
	pu, err := packageurl.FromString(purl)
	if err != nil || !osPackageTypes[strings.ToLower(pu.Type)] {
		return Identity{}, false
	}
	distro := strings.TrimSpace(pu.Qualifiers.Map()["distro"])
	ns := strings.ToLower(pu.Namespace)
	if distro == "" || ns == "" {
		return Identity{}, false
	}
	// Some inventories write "<id>-<version>"; drop a matching prefix.
	distro = strings.TrimPrefix(strings.ToLower(distro), ns+"-")
	return Identity{
		Distribution: ns,
		Release:      normalizeRelease(ns, distro),
		Version:      distro,
		Origin:       OriginOSPackage,
	}, true
}

// normalizeRelease maps a detected version to the cycle the dataset keys on.
// Values that cannot be normalized are returned unchanged and later reported
// as unknown.
func normalizeRelease(distribution, v string) string {
	switch distribution {
	case "alpine":
		// "3.18.12" is 3.18. Development snapshots (3.25.0_alpha...) and
		// edge have no end of life.
		if strings.Contains(v, "_") || v == "edge" {
			return "edge"
		}
		if parts := strings.Split(v, "."); len(parts) >= 2 && isDigits(parts[0]) && isDigits(parts[1]) {
			return parts[0] + "." + parts[1]
		}
	case "debian":
		// "12", "12.4", or a codename.
		if major, _, _ := strings.Cut(v, "."); isDigits(major) {
			return major
		}
	case "ubuntu":
		// "24.04", "24.04.1", or a codename.
		if parts := strings.Split(v, "."); len(parts) >= 2 && isDigits(parts[0]) && isDigits(parts[1]) {
			return parts[0] + "." + parts[1]
		}
	}
	return v
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

var (
	// alpineTagRE matches a tag segment naming an Alpine release, as in
	// node:20-alpine3.18 or python:3.12-alpine3.19.
	alpineTagRE = regexp.MustCompile(`^alpine(\d+\.\d+)$`)
	// distrolessRE matches distroless image names, which carry the Debian
	// release: gcr.io/distroless/static-debian12.
	distrolessRE = regexp.MustCompile(`-debian(\d+)$`)
)

// FromImageRef reads the release named by a container image reference
// (pkg:docker/library/alpine@3.18, pkg:oci/gcr.io/distroless/base-debian12).
// It recognizes the official alpine, debian, and ubuntu images, distroless
// images, and tags of other images that name a release in a dash-separated
// segment (node:20-alpine3.18, python:3.12-slim-bookworm). Codename segments
// are only taken when the dataset knows the codename, so an unrelated tag
// segment is not mistaken for a release. It reports false when the reference
// names no release (alpine:latest, a digest-only reference, an application
// image).
func (d *Dataset) FromImageRef(purl string) (Identity, bool) {
	pu, err := packageurl.FromString(purl)
	if err != nil {
		return Identity{}, false
	}
	typ := strings.ToLower(pu.Type)
	if typ != "docker" && typ != "oci" {
		return Identity{}, false
	}
	// Inventories write the repository path either as namespace and name or
	// whole in the name (pkg:docker/library%2Falpine@3.18); split it the
	// same way regardless.
	full := strings.ToLower(strings.Trim(pu.Namespace+"/"+pu.Name, "/"))
	ns, name := "", full
	if i := strings.LastIndex(full, "/"); i >= 0 {
		ns, name = full[:i], full[i+1:]
	}
	tag := strings.ToLower(pu.Version)
	if i := strings.Index(tag, "@"); i >= 0 {
		tag = tag[:i]
	}
	img := func(distro, release string) (Identity, bool) {
		return Identity{
			Distribution: distro,
			Release:      normalizeRelease(distro, release),
			Version:      release,
			Origin:       OriginImageRef,
		}, true
	}

	// Distroless names the Debian release in the image name, not the tag.
	if strings.HasSuffix(ns, "distroless") {
		if m := distrolessRE.FindStringSubmatch(name); m != nil {
			return img("debian", m[1])
		}
	}

	// Official distribution images: the first tag segment is the release.
	if (ns == "" || ns == "library" || ns == "docker.io/library") && d.Knows(name) {
		first, _, _ := strings.Cut(tag, "-")
		if first == "" || first == "latest" || first == "stable" || first == "edge" || strings.HasPrefix(first, "sha256:") {
			return Identity{}, false
		}
		return img(name, first)
	}

	// Derived images whose tag names the base release.
	for seg := range strings.SplitSeq(tag, "-") {
		if m := alpineTagRE.FindStringSubmatch(seg); m != nil {
			return img("alpine", m[1])
		}
		for _, distro := range []string{"debian", "ubuntu"} {
			if r, ok := d.Lookup(distro, seg); ok && r.Codename == seg {
				return img(distro, seg)
			}
		}
	}
	return Identity{}, false
}
