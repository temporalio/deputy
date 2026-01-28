package targets_test

import (
	"context"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	listv1 "github.com/picatz/deputy/gen/deputy/list/v1"
	"github.com/picatz/deputy/internal/targets"
)

func TestValidateTargetFilter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		filter  string
		wantErr bool
	}{
		{"empty filter", "", false},
		{"simple name check", "name == \"test\"", false},
		{"uri contains", "uri.contains(\"aws\")", false},
		{"metadata lookup", "metadata[\"env\"] == \"prod\"", false},
		{"timestamp comparison", "created_at > timestamp(\"2024-01-01T00:00:00Z\")", false},
		{"combined conditions", "name.startsWith(\"web-\") && metadata[\"team\"] == \"platform\"", false},
		{"invalid syntax", "name ==", true},
		{"unknown function", "unknown_func(name)", true},
		{"wrong return type", "name", true}, // returns string, not bool
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := targets.ValidateTargetFilter(tt.filter)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateTargetFilter() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestFilterDiscoveredTargets(t *testing.T) {
	t.Parallel()

	now := time.Now()
	past := now.Add(-24 * time.Hour)
	future := now.Add(24 * time.Hour)

	testTargets := []*listv1.DiscoveredTarget{
		{
			Uri:         "aws://ami/ami-prod-001",
			Name:        "web-server-prod",
			Description: "Production web server",
			CreatedAt:   timestamppb.New(past),
			Metadata: map[string]string{
				"env":  "prod",
				"team": "platform",
			},
		},
		{
			Uri:         "aws://ami/ami-dev-001",
			Name:        "web-server-dev",
			Description: "Development web server",
			CreatedAt:   timestamppb.New(future),
			Metadata: map[string]string{
				"env":  "dev",
				"team": "platform",
			},
		},
		{
			Uri:         "aws://ami/ami-staging-001",
			Name:        "api-server-staging",
			Description: "Staging API server",
			CreatedAt:   timestamppb.New(now),
			Metadata: map[string]string{
				"env":  "staging",
				"team": "backend",
			},
		},
	}

	tests := []struct {
		name      string
		filter    string
		wantCount int
		wantURIs  []string
	}{
		{
			name:      "empty filter returns all",
			filter:    "",
			wantCount: 3,
		},
		{
			name:      "filter by env metadata",
			filter:    `metadata["env"] == "prod"`,
			wantCount: 1,
			wantURIs:  []string{"aws://ami/ami-prod-001"},
		},
		{
			name:      "filter by name prefix",
			filter:    `name.startsWith("web-")`,
			wantCount: 2,
			wantURIs:  []string{"aws://ami/ami-prod-001", "aws://ami/ami-dev-001"},
		},
		{
			name:      "filter by team",
			filter:    `metadata["team"] == "platform"`,
			wantCount: 2,
		},
		{
			name:      "combined filter",
			filter:    `name.startsWith("web-") && metadata["env"] == "prod"`,
			wantCount: 1,
			wantURIs:  []string{"aws://ami/ami-prod-001"},
		},
		{
			name:      "filter by uri contains",
			filter:    `uri.contains("dev")`,
			wantCount: 1,
			wantURIs:  []string{"aws://ami/ami-dev-001"},
		},
		{
			name:      "no matches",
			filter:    `metadata["env"] == "nonexistent"`,
			wantCount: 0,
		},
		{
			name:      "filter by description",
			filter:    `description.contains("API")`,
			wantCount: 1,
			wantURIs:  []string{"aws://ami/ami-staging-001"},
		},
	}

	ctx := context.Background()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := targets.FilterDiscoveredTargets(ctx, testTargets, tt.filter)
			if err != nil {
				t.Fatalf("FilterDiscoveredTargets() error = %v", err)
			}

			if len(result) != tt.wantCount {
				t.Errorf("FilterDiscoveredTargets() returned %d targets, want %d", len(result), tt.wantCount)
			}

			if tt.wantURIs != nil {
				gotURIs := make([]string, len(result))
				for i, r := range result {
					gotURIs[i] = r.GetUri()
				}
				for _, wantURI := range tt.wantURIs {
					found := false
					for _, gotURI := range gotURIs {
						if gotURI == wantURI {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("expected URI %q not found in results %v", wantURI, gotURIs)
					}
				}
			}
		})
	}
}

func TestFilterDiscoveredTargets_InvalidFilter(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	testTargets := []*listv1.DiscoveredTarget{
		{Uri: "test://target", Name: "test"},
	}

	_, err := targets.FilterDiscoveredTargets(ctx, testTargets, "invalid syntax ==")
	if err == nil {
		t.Error("expected error for invalid filter, got nil")
	}
}

func TestFilterDiscoveredTargets_NilMetadata(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	testTargets := []*listv1.DiscoveredTarget{
		{
			Uri:      "test://target",
			Name:     "test",
			Metadata: nil, // nil metadata should not cause panic
		},
	}

	// Should not panic on nil metadata
	result, err := targets.FilterDiscoveredTargets(ctx, testTargets, `name == "test"`)
	if err != nil {
		t.Fatalf("FilterDiscoveredTargets() error = %v", err)
	}
	if len(result) != 1 {
		t.Errorf("expected 1 result, got %d", len(result))
	}
}

func TestFilterDiscoveredTargets_ZeroCreatedAt(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	testTargets := []*listv1.DiscoveredTarget{
		{
			Uri:       "test://target",
			Name:      "test",
			CreatedAt: nil, // nil created_at should not cause panic
		},
	}

	// Should not panic on nil created_at
	result, err := targets.FilterDiscoveredTargets(ctx, testTargets, `name == "test"`)
	if err != nil {
		t.Fatalf("FilterDiscoveredTargets() error = %v", err)
	}
	if len(result) != 1 {
		t.Errorf("expected 1 result, got %d", len(result))
	}
}
