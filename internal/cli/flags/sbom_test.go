package flags

import "testing"

func TestNormalizeSBOMInputFormat(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"", SBOMInputAuto},
		{"auto", SBOMInputAuto},
		{"protobom-json", SBOMInputProtobom},
		{"protobom", SBOMInputProtobom},
		{"cyclonedx-json", SBOMInputCycloneDX},
		{"cyclonedx", SBOMInputCycloneDX},
		{"spdx-json", SBOMInputSPDX},
		{"spdx", SBOMInputSPDX},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := NormalizeSBOMInputFormat(tt.in)
			if err != nil {
				t.Fatalf("NormalizeSBOMInputFormat(%q) error: %v", tt.in, err)
			}
			if got != tt.want {
				t.Fatalf("NormalizeSBOMInputFormat(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
	if _, err := NormalizeSBOMInputFormat("unknown"); err == nil {
		t.Fatalf("expected error for unknown input format")
	}
}

func TestNormalizeSBOMOutputFormat(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"", SBOMOutputCycloneDXJSON},
		{"cyclonedx-json", SBOMOutputCycloneDXJSON},
		{"cyclonedx", SBOMOutputCycloneDXJSON},
		{"spdx-json", SBOMOutputSPDXJSON},
		{"spdx", SBOMOutputSPDXJSON},
		{"protobom-json", SBOMOutputProtobomJSON},
		{"protobom", SBOMOutputProtobomJSON},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := NormalizeSBOMOutputFormat(tt.in)
			if err != nil {
				t.Fatalf("NormalizeSBOMOutputFormat(%q) error: %v", tt.in, err)
			}
			if got != tt.want {
				t.Fatalf("NormalizeSBOMOutputFormat(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
	if _, err := NormalizeSBOMOutputFormat("unknown"); err == nil {
		t.Fatalf("expected error for unknown output format")
	}
}
