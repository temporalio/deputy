// Package regression holds recorded inventories of public container images,
// pinned by digest, for tests that need real-world package shapes without the
// network: split OS packages and their source names, distroless status.d
// databases, images that bundle many Go binaries, end-of-life base releases.
//
// Each file in images/ is the output of
//
//	deputy list --source remote --platform linux/amd64 <repo>:<tag>@<digest> --format json
//
// reduced to the package fields tests read, with the image reference, digest,
// platform, and recording date alongside. Re-record a file the same way when a
// change to inventory extraction is intended; the live test in this package
// (DEPUTY_REGRESSION_E2E=1) scans the same digests end to end.
//
// Only public images belong here.
package regression

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"

	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
)

//go:embed images/*.json
var images embed.FS

// Image is one recorded image inventory.
type Image struct {
	// Image is the reference as tagged, e.g. "alpine:3.24.0".
	Image string `json:"image"`
	// Digest is the image index digest the recording was taken from.
	Digest string `json:"digest"`
	// Platform is the platform inventoried, e.g. "linux/amd64".
	Platform string `json:"platform"`
	// Recorded is the recording date, YYYY-MM-DD.
	Recorded string `json:"recorded"`
	// Packages is the inventory, sorted by PURL.
	Packages []*dependencyv1.Package `json:"packages"`
}

// Ref returns the digest-pinned reference, e.g.
// "alpine:3.24.0@sha256:...".
func (i *Image) Ref() string {
	return i.Image + "@" + i.Digest
}

// Load reads a recorded image by file name without extension, e.g.
// "alpine-3.24.0".
func Load(name string) (*Image, error) {
	data, err := images.ReadFile(path.Join("images", name+".json"))
	if err != nil {
		return nil, fmt.Errorf("regression image %q: %w", name, err)
	}
	var img Image
	if err := json.Unmarshal(data, &img); err != nil {
		return nil, fmt.Errorf("decode regression image %q: %w", name, err)
	}
	return &img, nil
}

// Names lists the recorded images, sorted.
func Names() []string {
	entries, _ := fs.ReadDir(images, "images")
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, strings.TrimSuffix(e.Name(), ".json"))
	}
	slices.Sort(out)
	return out
}
