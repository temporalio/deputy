package registry

import (
	"testing"
	"time"

	pb "deps.dev/api/v3"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestSystemFromEcosystem(t *testing.T) {
	tests := []struct {
		ecosystem string
		want      pb.System
	}{
		{"go", pb.System_GO},
		{"Go", pb.System_GO},
		{"golang", pb.System_GO},
		{"npm", pb.System_NPM},
		{"NodeJS", pb.System_NPM},
		{"pypi", pb.System_PYPI},
		{"python", pb.System_PYPI},
		{"cargo", pb.System_CARGO},
		{"maven", pb.System_MAVEN},
		{"rubygems", pb.System_RUBYGEMS},
		{"nuget", pb.System_NUGET},
		{"  npm  ", pb.System_NPM},
		{"hex", pb.System_SYSTEM_UNSPECIFIED},
		{"", pb.System_SYSTEM_UNSPECIFIED},
	}
	for _, tt := range tests {
		t.Run(tt.ecosystem, func(t *testing.T) {
			if got := systemFromEcosystem(tt.ecosystem); got != tt.want {
				t.Errorf("systemFromEcosystem(%q) = %v, want %v", tt.ecosystem, got, tt.want)
			}
		})
	}
}

func TestNormalizeVersion(t *testing.T) {
	tests := []struct {
		name    string
		system  pb.System
		version string
		want    string
	}{
		{"go gets v prefix", pb.System_GO, "1.2.3", "v1.2.3"},
		{"go keeps existing v", pb.System_GO, "v1.2.3", "v1.2.3"},
		{"go trims space", pb.System_GO, "  1.2.3 ", "v1.2.3"},
		{"npm untouched", pb.System_NPM, "1.2.3", "1.2.3"},
		{"empty stays empty", pb.System_GO, "  ", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeVersion(tt.system, tt.version); got != tt.want {
				t.Errorf("normalizeVersion(%v, %q) = %q, want %q", tt.system, tt.version, got, tt.want)
			}
		})
	}
}

func TestMetadataFromVersion(t *testing.T) {
	published := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	t.Run("nil version", func(t *testing.T) {
		if got := metadataFromVersion(nil); got != nil {
			t.Fatalf("metadataFromVersion(nil) = %v, want nil", got)
		}
	})

	t.Run("with publish date and registries", func(t *testing.T) {
		v := &pb.Version{
			PublishedAt: timestamppb.New(published),
			Registries:  []string{"https://registry.npmjs.org/"},
		}
		got := metadataFromVersion(v)
		if !got.PublishedAt.Equal(published) {
			t.Errorf("PublishedAt = %v, want %v", got.PublishedAt, published)
		}
		if len(got.Registries) != 1 || got.Registries[0] != "https://registry.npmjs.org/" {
			t.Errorf("Registries = %v", got.Registries)
		}
	})

	t.Run("missing publish date leaves zero time", func(t *testing.T) {
		got := metadataFromVersion(&pb.Version{})
		if !got.PublishedAt.IsZero() {
			t.Errorf("PublishedAt = %v, want zero", got.PublishedAt)
		}
	})
}

func TestMetadataToProto(t *testing.T) {
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)

	t.Run("nil receiver", func(t *testing.T) {
		var m *Metadata
		if got := m.ToProto(now); got != nil {
			t.Fatalf("ToProto() = %v, want nil", got)
		}
	})

	t.Run("computes age in days", func(t *testing.T) {
		m := &Metadata{
			PublishedAt: now.Add(-7 * 24 * time.Hour),
			Registries:  []string{"r"},
		}
		got := m.ToProto(now)
		if got.GetAgeDays() != 7 {
			t.Errorf("AgeDays = %v, want 7", got.GetAgeDays())
		}
		if got.GetPublishedAt() == nil {
			t.Error("PublishedAt = nil, want set")
		}
	})

	t.Run("unknown publish date yields -1 age and nil timestamp", func(t *testing.T) {
		m := &Metadata{}
		got := m.ToProto(now)
		if got.GetAgeDays() != -1 {
			t.Errorf("AgeDays = %v, want -1", got.GetAgeDays())
		}
		if got.GetPublishedAt() != nil {
			t.Error("PublishedAt should be nil when unknown")
		}
	})
}
