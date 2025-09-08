package compare

import (
	"testing"

	"github.com/google/osv-scalibr/extractor"
)

func Test_ParseGoPackage(t *testing.T) {
	tests := []struct {
		name, version, canon string
		major                int
	}{
		{"modernc.org/cc/v3", "3.41.0", "modernc.org/cc", 3},
		{"modernc.org/cc/v4", "4.24.4", "modernc.org/cc", 4},
		{"modernc.org/cc", "1.0.0", "modernc.org/cc", 1},
		{"github.com/example/pkg/v2", "2.1.0", "github.com/example/pkg", 2},
		{"gopkg.in/go-jose/go-jose.v2", "2.6.3", "github.com/go-jose/go-jose", 2},
		{"gopkg.in/yaml.v3", "3.0.1", "github.com/go-yaml/yaml", 3},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			p := &extractor.Package{Name: tt.name, Version: tt.version}
			info := ParseGoPackage(p)
			if info.OriginalName != tt.name {
				t.Fatalf("OriginalName got %q want %q", info.OriginalName, tt.name)
			}
			if info.CanonicalName != tt.canon {
				t.Fatalf("CanonicalName got %q want %q (Full=%q)", info.CanonicalName, tt.canon, info.FullName)
			}
			if info.MajorVersion != tt.major {
				t.Fatalf("MajorVersion got %d want %d (Full=%q Canon=%q)", info.MajorVersion, tt.major, info.FullName, info.CanonicalName)
			}
		})
	}
}
