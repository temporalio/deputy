package cmd

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	vulnerabilityv1 "github.com/picatz/deputy/gen/deputy/vulnerability/v1"
	"github.com/picatz/deputy/internal/analysis/osv"
	sbomx "github.com/picatz/deputy/internal/sbom"
	"github.com/picatz/deputy/internal/scan"
	"github.com/picatz/deputy/internal/vulnerability"
)

func TestSBOMImageRoundTrip(t *testing.T) {
	t.Parallel()

	tarPath := buildTestImageTarball(t)
	target := "tarball://" + tarPath

	result, err := sbomx.GenerateImage(context.Background(), target, nil, sbomx.Options{
		Ecosystems: []string{"go"},
	})
	if err != nil {
		t.Fatalf("GenerateImage: %v", err)
	}
	if len(result.Packages) == 0 {
		t.Fatal("expected packages from image SBOM generation")
	}

	var buf bytes.Buffer
	if err := sbomx.WriteProtobomJSON(result.Document, &buf); err != nil {
		t.Fatalf("WriteProtobomJSON: %v", err)
	}

	pkgs, direct, _, _, err := parseSBOMPackages(buf.Bytes(), "protobom-json")
	if err != nil {
		t.Fatalf("parseSBOMPackages: %v", err)
	}
	if len(pkgs) == 0 {
		t.Fatal("expected packages parsed from image SBOM")
	}

	var calls [][]osv.PkgInput
	svc := scan.NewServiceWithConfig(&scan.ServiceConfig{
		QueryVulnerabilities: func(ctx context.Context, client osv.Client, inputs []osv.PkgInput) ([]vulnerability.Finding, map[string]*vulnerabilityv1.Advisory, error) {
			copied := append([]osv.PkgInput(nil), inputs...)
			calls = append(calls, copied)
			return nil, nil, nil
		},
	})

	if _, err := svc.ScanContainerImage(context.Background(), target, nil, scan.Options{Ecosystems: []string{"go"}}); err != nil {
		t.Fatalf("ScanContainerImage: %v", err)
	}
	if _, err := svc.ScanSBOM(context.Background(), pkgs, direct, scan.Options{Ecosystems: []string{"go"}}); err != nil {
		t.Fatalf("ScanSBOM: %v", err)
	}

	if len(calls) != 2 {
		t.Fatalf("expected 2 OSV query calls, got %d", len(calls))
	}
	imageInputs := inputKeys(calls[0])
	sbomInputs := inputKeys(calls[1])
	if !slices.Equal(imageInputs, sbomInputs) {
		t.Fatalf("image vs sbom inputs mismatch:\nimage=%v\nsbom=%v", imageInputs, sbomInputs)
	}
}

func buildTestImageTarball(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	layerPath := filepath.Join(dir, "layer.tar")
	files := map[string]string{
		"go.mod": "module example.com/image\n\ngo 1.21\n\nrequire github.com/pkg/errors v0.9.1\n",
		"go.sum": "github.com/pkg/errors v0.9.1 h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=\n" +
			"github.com/pkg/errors v0.9.1/go.mod h1:bwawxfHBFNV+L2hUp1rHADufV3IMtnDRdf1r5NINEl0=\n",
	}
	writeTar(t, layerPath, files)

	layer, err := tarball.LayerFromFile(layerPath)
	if err != nil {
		t.Fatalf("LayerFromFile: %v", err)
	}
	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		t.Fatalf("AppendLayers: %v", err)
	}
	tag, err := name.NewTag("example.com/deputy/test:latest", name.WeakValidation)
	if err != nil {
		t.Fatalf("NewTag: %v", err)
	}

	tarPath := filepath.Join(dir, "image.tar")
	if err := tarball.WriteToFile(tarPath, tag, img); err != nil {
		t.Fatalf("WriteToFile: %v", err)
	}
	return tarPath
}

func writeTar(t *testing.T, path string, files map[string]string) {
	t.Helper()

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create tar: %v", err)
	}
	defer f.Close()

	tw := tar.NewWriter(f)
	defer tw.Close()

	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	slices.Sort(names)

	for _, name := range names {
		data := []byte(files[name])
		hdr := &tar.Header{
			Name:     name,
			Mode:     0o644,
			Size:     int64(len(data)),
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write tar header: %v", err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatalf("write tar data: %v", err)
		}
	}
}

func inputKeys(inputs []osv.PkgInput) []string {
	out := make([]string, 0, len(inputs))
	for _, in := range inputs {
		key := strings.TrimSpace(in.PURL)
		if key == "" {
			key = fmt.Sprintf("%s|%s|%s", in.Ecosystem, in.Name, in.Version)
		}
		out = append(out, key)
	}
	slices.Sort(out)
	return out
}

// TestSBOMLayerDetailsRoundTrip verifies that container image layer details
// are preserved when generating an SBOM and parsing it back.
func TestSBOMLayerDetailsRoundTrip(t *testing.T) {
	t.Parallel()

	// Build a multi-layer test image
	tarPath := buildMultiLayerTestImage(t)
	target := "tarball://" + tarPath

	result, err := sbomx.GenerateImage(context.Background(), target, nil, sbomx.Options{
		Ecosystems: []string{"go"},
	})
	if err != nil {
		t.Fatalf("GenerateImage: %v", err)
	}
	if len(result.Packages) == 0 {
		t.Fatal("expected packages from image SBOM generation")
	}

	// Check if any packages have layer details before serialization
	hasLayerDetails := false
	for _, pkg := range result.Packages {
		if pkg.LayerDetails != nil {
			hasLayerDetails = true
			break
		}
	}
	t.Logf("Packages with layer details before SBOM: %v", hasLayerDetails)

	// Serialize to SBOM
	var buf bytes.Buffer
	if err := sbomx.WriteProtobomJSON(result.Document, &buf); err != nil {
		t.Fatalf("WriteProtobomJSON: %v", err)
	}

	// Check the SBOM contains layer properties
	sbomContent := buf.String()
	if hasLayerDetails {
		if !strings.Contains(sbomContent, "deputy:layer-") {
			t.Log("Warning: packages had layer details but SBOM doesn't contain layer properties")
		}
	}

	// Parse the SBOM back
	pkgs, _, _, _, err := parseSBOMPackages(buf.Bytes(), "protobom-json")
	if err != nil {
		t.Fatalf("parseSBOMPackages: %v", err)
	}
	if len(pkgs) == 0 {
		t.Fatal("expected packages parsed from image SBOM")
	}

	// Verify layer details are preserved if they existed
	if hasLayerDetails {
		restoredWithLayers := 0
		for _, pkg := range pkgs {
			if pkg.LayerDetails != nil {
				restoredWithLayers++
				// Verify layer fields are populated
				if pkg.LayerDetails.Index < 0 {
					t.Errorf("restored layer index is negative: %d", pkg.LayerDetails.Index)
				}
			}
		}
		if restoredWithLayers == 0 {
			t.Error("expected at least one package with restored layer details")
		}
		t.Logf("Packages with restored layer details: %d/%d", restoredWithLayers, len(pkgs))
	}
}

// buildMultiLayerTestImage creates a tarball with multiple layers
// to better test layer detail attribution.
func buildMultiLayerTestImage(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()

	// Layer 1: Base system files (simulating base image)
	layer1Path := filepath.Join(dir, "layer1.tar")
	writeTar(t, layer1Path, map[string]string{
		"etc/os-release": "ID=debian\nVERSION_ID=\"11\"\n",
	})

	// Layer 2: Application dependencies
	layer2Path := filepath.Join(dir, "layer2.tar")
	writeTar(t, layer2Path, map[string]string{
		"app/go.mod": "module example.com/app\n\ngo 1.21\n\nrequire github.com/pkg/errors v0.9.1\n",
		"app/go.sum": "github.com/pkg/errors v0.9.1 h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=\n" +
			"github.com/pkg/errors v0.9.1/go.mod h1:bwawxfHBFNV+L2hUp1rHADufV3IMtnDRdf1r5NINEl0=\n",
	})

	layer1, err := tarball.LayerFromFile(layer1Path)
	if err != nil {
		t.Fatalf("LayerFromFile layer1: %v", err)
	}
	layer2, err := tarball.LayerFromFile(layer2Path)
	if err != nil {
		t.Fatalf("LayerFromFile layer2: %v", err)
	}

	img, err := mutate.AppendLayers(empty.Image, layer1, layer2)
	if err != nil {
		t.Fatalf("AppendLayers: %v", err)
	}

	tag, err := name.NewTag("example.com/deputy/multilayer:latest", name.WeakValidation)
	if err != nil {
		t.Fatalf("NewTag: %v", err)
	}

	tarPath := filepath.Join(dir, "multilayer.tar")
	if err := tarball.WriteToFile(tarPath, tag, img); err != nil {
		t.Fatalf("WriteToFile: %v", err)
	}
	return tarPath
}
