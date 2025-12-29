package license

import (
	"context"
	"errors"
	"testing"

	pb "deps.dev/api/v3"
)

// fakeDepsClientOK simulates a successful deps.dev API response with a known license.
type fakeDepsClientOK struct{}

func (f *fakeDepsClientOK) GetVersion(ctx context.Context, req *pb.GetVersionRequest) (*pb.Version, error) {
	return &pb.Version{Licenses: []string{"MIT"}}, nil
}

// fakeDepsClientErr simulates a deps.dev API failure.
type fakeDepsClientErr struct{}

func (f *fakeDepsClientErr) GetVersion(ctx context.Context, req *pb.GetVersionRequest) (*pb.Version, error) {
	return nil, errors.New("network")
}

func Test_FetchLicensesForPackage_success(t *testing.T) {
	ResetLicenseCachesForTest(t)
	client := &fakeDepsClientOK{}
	got := FetchLicensesForPackage(context.Background(), client, "github.com/example/pkg", "1.2.3")
	if len(got) != 1 || got[0] != "MIT" {
		t.Fatalf("unexpected licenses: %v", got)
	}
}

func Test_FetchLicensesForPackage_error_returns_unknown(t *testing.T) {
	ResetLicenseCachesForTest(t)
	client := &fakeDepsClientErr{}
	got := FetchLicensesForPackage(context.Background(), client, "github.com/example/pkg", "1.2.3")
	if len(got) != 1 || got[0] != "?" {
		t.Fatalf("expected unknown license on error, got %v", got)
	}
}

// countingDepsClient tracks the number of API calls made.
type countingDepsClient struct{ calls int }

func (c *countingDepsClient) GetVersion(ctx context.Context, req *pb.GetVersionRequest) (*pb.Version, error) {
	c.calls++
	return &pb.Version{Licenses: []string{"Apache-2.0"}}, nil
}

func Test_FetchLicensesForPackage_cache(t *testing.T) {
	ResetLicenseCachesForTest(t)
	client := &countingDepsClient{}
	FetchLicensesForPackage(context.Background(), client, "github.com/example/pkg", "1.2.3")
	FetchLicensesForPackage(context.Background(), client, "github.com/example/pkg", "1.2.3")
	if client.calls != 1 {
		t.Fatalf("expected 1 call, got %d", client.calls)
	}
}
