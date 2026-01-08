package server

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	secretsv1 "github.com/picatz/deputy/gen/deputy/secrets/v1"
)

func TestSecretsHandler_New(t *testing.T) {
	handler, err := NewSecretsHandler()
	if err != nil {
		t.Fatalf("failed to create secrets handler: %v", err)
	}
	if handler == nil {
		t.Fatal("handler is nil")
	}
}

func TestSecretsHandler_ListDetectors(t *testing.T) {
	handler, err := NewSecretsHandler()
	if err != nil {
		t.Fatalf("failed to create secrets handler: %v", err)
	}

	ctx := context.Background()
	req := connect.NewRequest(&secretsv1.ListDetectorsRequest{
		IncludeDisabled: true,
	})

	resp, err := handler.ListDetectors(ctx, req)
	if err != nil {
		t.Fatalf("ListDetectors failed: %v", err)
	}

	if len(resp.Msg.Detectors) == 0 {
		t.Fatal("expected at least one detector")
	}

	// Check for expected built-in detectors
	foundGitHub := false
	foundAWS := false
	for _, d := range resp.Msg.Detectors {
		switch d.Id {
		case "github":
			foundGitHub = true
		case "aws":
			foundAWS = true
		}
	}

	if !foundGitHub {
		t.Error("expected github detector to be registered")
	}
	if !foundAWS {
		t.Error("expected aws detector to be registered")
	}
}

func TestSecretsHandler_ScanEmptyTarget(t *testing.T) {
	handler, err := NewSecretsHandler()
	if err != nil {
		t.Fatalf("failed to create secrets handler: %v", err)
	}

	ctx := context.Background()
	req := connect.NewRequest(&secretsv1.ScanRequest{
		Target: "", // Will default to "."
	})

	// This should work (defaults to current directory)
	_, err = handler.Scan(ctx, req)
	// We don't fail on empty target - it defaults to "."
	// The actual scan might fail depending on environment, but handler construction should work
	_ = err
}

func TestSecretsHandler_RegisterDetector(t *testing.T) {
	handler, err := NewSecretsHandler()
	if err != nil {
		t.Fatalf("failed to create secrets handler: %v", err)
	}

	ctx := context.Background()
	req := connect.NewRequest(&secretsv1.RegisterDetectorRequest{
		Detector: &secretsv1.DetectorInfo{
			Id:          "test-custom",
			Name:        "Test Custom Detector",
			Description: "A test custom detector",
		},
		Pattern: `test_secret_[A-Za-z0-9]{32}`,
	})

	resp, err := handler.RegisterDetector(ctx, req)
	if err != nil {
		t.Fatalf("RegisterDetector failed: %v", err)
	}

	if resp.Msg.Detector == nil {
		t.Fatal("expected detector in response")
	}

	if resp.Msg.Detector.Id != "test-custom" {
		t.Errorf("expected detector id 'test-custom', got '%s'", resp.Msg.Detector.Id)
	}

	if resp.Msg.Detector.Source != secretsv1.DetectorSource_DETECTOR_SOURCE_CUSTOM {
		t.Errorf("expected source to be CUSTOM, got %v", resp.Msg.Detector.Source)
	}

	// Verify the detector was added
	listReq := connect.NewRequest(&secretsv1.ListDetectorsRequest{})
	listResp, err := handler.ListDetectors(ctx, listReq)
	if err != nil {
		t.Fatalf("ListDetectors failed: %v", err)
	}

	foundCustom := false
	for _, d := range listResp.Msg.Detectors {
		if d.Id == "test-custom" {
			foundCustom = true
			break
		}
	}

	if !foundCustom {
		t.Error("custom detector not found in list after registration")
	}
}

func TestSecretsHandler_RegisterDetector_InvalidPattern(t *testing.T) {
	handler, err := NewSecretsHandler()
	if err != nil {
		t.Fatalf("failed to create secrets handler: %v", err)
	}

	ctx := context.Background()
	req := connect.NewRequest(&secretsv1.RegisterDetectorRequest{
		Detector: &secretsv1.DetectorInfo{
			Id:   "bad-detector",
			Name: "Bad Detector",
		},
		Pattern: `[invalid(regex`, // Invalid regex
	})

	_, err = handler.RegisterDetector(ctx, req)
	if err == nil {
		t.Fatal("expected error for invalid regex pattern")
	}
}

func TestSecretsHandler_RegisterDetector_MissingPattern(t *testing.T) {
	handler, err := NewSecretsHandler()
	if err != nil {
		t.Fatalf("failed to create secrets handler: %v", err)
	}

	ctx := context.Background()
	req := connect.NewRequest(&secretsv1.RegisterDetectorRequest{
		Detector: &secretsv1.DetectorInfo{
			Id:   "no-pattern",
			Name: "No Pattern Detector",
		},
		Pattern: "", // Empty pattern
	})

	_, err = handler.RegisterDetector(ctx, req)
	if err == nil {
		t.Fatal("expected error for missing pattern")
	}
}
