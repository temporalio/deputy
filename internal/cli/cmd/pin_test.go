package cmd

import (
	"context"
	"strings"
	"testing"

	"github.com/picatz/deputy/internal/pin"
)

func TestBuildPinStrategies(t *testing.T) {
	tests := []struct {
		name       string
		ecosystems []string
		wantLen    int
		wantErr    string
	}{
		{
			name:       "default github-actions",
			ecosystems: []string{"github-actions"},
			wantLen:    1,
		},
		{
			name:       "all expands to supported",
			ecosystems: []string{"all"},
			wantLen:    len(supportedPinEcosystems), // github-actions + container-image
		},
		{
			name:       "container-image",
			ecosystems: []string{"container-image"},
			wantLen:    1,
		},
		{
			name:       "unsupported ecosystem",
			ecosystems: []string{"npm"},
			wantErr:    "unsupported ecosystem for pinning",
		},
		{
			name:       "mixed valid and invalid",
			ecosystems: []string{"github-actions", "cargo"},
			wantErr:    "unsupported ecosystem for pinning",
		},
		{
			name:       "deduplicates",
			ecosystems: []string{"github-actions", "github-actions"},
			wantLen:    1,
		},
		{
			name:       "empty slice",
			ecosystems: []string{},
			wantErr:    "no ecosystems selected",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			strategies, err := buildPinStrategies(context.Background(), tc.ecosystems, false)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(strategies) != tc.wantLen {
				t.Errorf("expected %d strategies, got %d", tc.wantLen, len(strategies))
			}
			for _, s := range strategies {
				eco := s.Ecosystem()
				if eco != pin.EcosystemGitHubActions && eco != pin.EcosystemContainerImage {
					t.Errorf("unexpected ecosystem: %s", eco)
				}
			}
		})
	}
}
