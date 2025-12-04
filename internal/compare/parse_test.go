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
		{name: "modernc.org/cc/v3", version: "3.41.0", canon: "modernc.org/cc", major: 3},
		{name: "modernc.org/cc/v4", version: "4.24.4", canon: "modernc.org/cc", major: 4},
		{name: "modernc.org/cc", version: "1.0.0", canon: "modernc.org/cc", major: 1},
		{name: "github.com/example/pkg/v2", version: "2.1.0", canon: "github.com/example/pkg", major: 2},
		{name: "gopkg.in/go-jose/go-jose.v2", version: "2.6.3", canon: "github.com/go-jose/go-jose", major: 2},
		{name: "gopkg.in/yaml.v3", version: "3.0.1", canon: "github.com/go-yaml/yaml", major: 3},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p := &extractor.Package{Name: test.name, Version: test.version}
			info := ParseGoPackage(p)
			if info.OriginalName != test.name {
				t.Fatalf("OriginalName got %q want %q", info.OriginalName, test.name)
			}
			if info.CanonicalName != test.canon {
				t.Fatalf("CanonicalName got %q want %q (Full=%q)", info.CanonicalName, test.canon, info.FullName)
			}
			if info.MajorVersion != test.major {
				t.Fatalf("MajorVersion got %d want %d (Full=%q Canon=%q)", info.MajorVersion, test.major, info.FullName, info.CanonicalName)
			}
		})
	}
}
