package analysis

import (
    "context"
    "errors"
    "testing"

    pb "deps.dev/api/v3"
)

type fakeDepsClientOK struct{}

func (f *fakeDepsClientOK) GetVersion(ctx context.Context, req *pb.GetVersionRequest) (*pb.Version, error) {
    return &pb.Version{Licenses: []string{"MIT"}}, nil
}

type fakeDepsClientErr struct{}

func (f *fakeDepsClientErr) GetVersion(ctx context.Context, req *pb.GetVersionRequest) (*pb.Version, error) {
    return nil, errors.New("network")
}

func Test_FetchLicensesForPackage_success(t *testing.T) {
    client := &fakeDepsClientOK{}
    got := FetchLicensesForPackage(context.Background(), client, "github.com/example/pkg", "1.2.3")
    if len(got) != 1 || got[0] != "MIT" {
        t.Fatalf("unexpected licenses: %v", got)
    }
}

func Test_FetchLicensesForPackage_error_returns_unknown(t *testing.T) {
    client := &fakeDepsClientErr{}
    got := FetchLicensesForPackage(context.Background(), client, "github.com/example/pkg", "1.2.3")
    if len(got) != 1 || got[0] != "?" {
        t.Fatalf("expected unknown license on error, got %v", got)
    }
}

