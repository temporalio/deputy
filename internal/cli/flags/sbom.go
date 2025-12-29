package flags

import "strings"

const (
	SBOMInputAuto      = "auto"
	SBOMInputProtobom  = "protobom"
	SBOMInputCycloneDX = "cyclonedx"
	SBOMInputSPDX      = "spdx"
)

const (
	SBOMOutputCycloneDXJSON = "cyclonedx-json"
	SBOMOutputSPDXJSON      = "spdx-json"
	SBOMOutputProtobomJSON  = "protobom-json"
)

// NormalizeSBOMInputFormat maps input format aliases to a canonical base format.
func NormalizeSBOMInputFormat(format string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", SBOMInputAuto:
		return SBOMInputAuto, nil
	case SBOMInputProtobom, SBOMOutputProtobomJSON:
		return SBOMInputProtobom, nil
	case SBOMInputCycloneDX, SBOMOutputCycloneDXJSON:
		return SBOMInputCycloneDX, nil
	case SBOMInputSPDX, SBOMOutputSPDXJSON:
		return SBOMInputSPDX, nil
	default:
		return "", UnsupportedFormatError("--input-format", format, "auto|protobom-json|cyclonedx-json|spdx-json")
	}
}

// NormalizeSBOMOutputFormat maps output format aliases to a canonical JSON format.
func NormalizeSBOMOutputFormat(format string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", SBOMOutputCycloneDXJSON, SBOMInputCycloneDX:
		return SBOMOutputCycloneDXJSON, nil
	case SBOMOutputSPDXJSON, SBOMInputSPDX:
		return SBOMOutputSPDXJSON, nil
	case SBOMOutputProtobomJSON, SBOMInputProtobom:
		return SBOMOutputProtobomJSON, nil
	default:
		return "", UnsupportedFormatError("", format, "cyclonedx-json | spdx-json | protobom-json")
	}
}
