package main

import (
	"context"
	"errors"
	"testing"

	pb "deps.dev/api/v3"
)

type fakeDepsClientOK struct{}

func (f *fakeDepsClientOK) GetVersion(ctx context.Context, req *pb.GetVersionRequest) (*pb.Version, error) {
	return &pb.Version{
		Licenses: []string{"MIT"},
	}, nil
}

type fakeDepsClientErr struct{}

func (f *fakeDepsClientErr) GetVersion(ctx context.Context, req *pb.GetVersionRequest) (*pb.Version, error) {
	return nil, errors.New("network")
}

func Test_fetchLicensesForPackage_success(t *testing.T) {
	client := &fakeDepsClientOK{}
	pkg := PackageChange{Name: "github.com/example/pkg", TargetVersion: "1.2.3"}
	got := fetchLicensesForPackage(t.Context(), client, pkg)
	if len(got) != 1 || got[0] != "MIT" {
		t.Fatalf("unexpected licenses: %v", got)
	}
}

func Test_fetchLicensesForPackage_error_returns_unknown(t *testing.T) {
	client := &fakeDepsClientErr{}
	pkg := PackageChange{Name: "github.com/example/pkg", TargetVersion: "1.2.3"}
	got := fetchLicensesForPackage(t.Context(), client, pkg)
	if len(got) != 1 || got[0] != "?" {
		t.Fatalf("expected unknown license on error, got %v", got)
	}
}
