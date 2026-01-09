// Copyright 2025 Kent "picat" Gruber. All rights reserved.
// SPDX-License-Identifier: MIT

package proto

import (
	"github.com/google/osv-scalibr/extractor"

	containerv1 "github.com/picatz/deputy/gen/deputy/container/v1"
	dependencyv1 "github.com/picatz/deputy/gen/deputy/dependency/v1"
	"github.com/picatz/deputy/internal/compare"
)

// ExtractorPackageToProto converts an OSV-SCALIBR extractor.Package to proto Package.
// The direct map indicates which packages are direct dependencies. For Go packages,
// the map keys are module roots (e.g., "github.com/google/osv-scalibr"). For other
// ecosystems, keys are PURL strings.
func ExtractorPackageToProto(pkg *extractor.Package, direct map[string]bool) *dependencyv1.Package {
	if pkg == nil {
		return nil
	}

	purl := pkg.PURL()
	purlStr := ""
	if purl != nil {
		purlStr = purl.String()
	}

	isDirect := false
	if direct != nil && purl != nil {
		// Direct map contains Go module roots (e.g., "github.com/google/osv-scalibr"),
		// not PURL strings. For Go packages, use the module root for lookup.
		if purl.Type == "golang" {
			// Reconstruct module path from PURL namespace + name
			modulePath := pkg.Name
			if modulePath == "" {
				if purl.Namespace != "" {
					modulePath = purl.Namespace + "/" + purl.Name
				} else {
					modulePath = purl.Name
				}
			}
			moduleRoot := compare.GetModuleRoot(modulePath)
			isDirect = direct[moduleRoot]
		} else {
			// For non-Go ecosystems, use PURL string as key
			isDirect = direct[purlStr]
		}
	}

	var layerDetails *containerv1.LayerDetails
	if pkg.LayerDetails != nil {
		layerDetails = &containerv1.LayerDetails{
			Index:       int32(pkg.LayerDetails.Index),
			DiffId:      pkg.LayerDetails.DiffID,
			ChainId:     pkg.LayerDetails.ChainID,
			Command:     pkg.LayerDetails.Command,
			InBaseImage: pkg.LayerDetails.InBaseImage,
		}
	}

	return &dependencyv1.Package{
		Name:         pkg.Name,
		Ecosystem:    pkg.Ecosystem(),
		Version:      pkg.Version,
		Purl:         purlStr,
		Direct:       isDirect,
		Locations:    pkg.Locations,
		Licenses:     pkg.Licenses,
		LayerDetails: layerDetails,
	}
}

// ExtractorPackagesToProto converts a slice of OSV-SCALIBR packages to proto Packages.
// The direct map indicates which packages are direct dependencies. For Go packages,
// the map keys are module roots (e.g., "github.com/google/osv-scalibr"). For other
// ecosystems, keys are PURL strings.
func ExtractorPackagesToProto(pkgs []*extractor.Package, direct map[string]bool) []*dependencyv1.Package {
	if len(pkgs) == 0 {
		return nil
	}
	out := make([]*dependencyv1.Package, len(pkgs))
	for i, pkg := range pkgs {
		out[i] = ExtractorPackageToProto(pkg, direct)
	}
	return out
}

// ExtractorPackagesFromProto converts proto Packages back to a simplified representation.
// Note: This is a lossy conversion as extractor.Package contains fields that aren't
// stored in the proto (e.g., Metadata, SourceCode, Plugins). This is primarily useful
// for testing or when you only need the basic package identity fields.
//
// For full fidelity, store the original extractor.Package or re-extract from source.
func ExtractorPackagesFromProto(pkgs []*dependencyv1.Package) ([]*extractor.Package, map[string]bool) {
	if len(pkgs) == 0 {
		return nil, nil
	}
	out := make([]*extractor.Package, len(pkgs))
	direct := make(map[string]bool)

	for i, pkg := range pkgs {
		if pkg == nil {
			continue
		}

		var layerDetails *extractor.LayerDetails
		if pkg.LayerDetails != nil {
			layerDetails = &extractor.LayerDetails{
				Index:       int(pkg.LayerDetails.Index),
				DiffID:      pkg.LayerDetails.DiffId,
				ChainID:     pkg.LayerDetails.ChainId,
				Command:     pkg.LayerDetails.Command,
				InBaseImage: pkg.LayerDetails.InBaseImage,
			}
		}

		out[i] = &extractor.Package{
			Name:         pkg.Name,
			Version:      pkg.Version,
			Locations:    pkg.Locations,
			Licenses:     pkg.Licenses,
			LayerDetails: layerDetails,
			// Note: PURLType and other fields cannot be reliably reconstructed
			// from the proto representation. The Ecosystem() method won't work
			// on these reconstructed packages without PURLType.
		}

		if pkg.Direct && pkg.Purl != "" {
			direct[pkg.Purl] = true
		}
	}
	return out, direct
}
