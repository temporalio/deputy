package compare

import (
	"testing"
)

func Test_NormalizeGopkgInURL_and_ExtractCanonical(t *testing.T) {
	cases := []struct{ in, norm, canon string }{
		{"gopkg.in/go-jose/go-jose.v2", "github.com/go-jose/go-jose", "github.com/go-jose/go-jose"},
		{"gopkg.in/yaml.v3", "github.com/go-yaml/yaml", "github.com/go-yaml/yaml"},
		{"gopkg.in/user/repo/subpkg.v2", "github.com/user/repo/subpkg", "github.com/user/repo/subpkg"},
		{"modernc.org/cc/v3", "modernc.org/cc/v3", "modernc.org/cc"},
		{"github.com/example/pkg/v10", "github.com/example/pkg/v10", "github.com/example/pkg"},
		{"github.com/example/pkg/v1", "github.com/example/pkg/v1", "github.com/example/pkg/v1"},
	}
	for _, c := range cases {
		if got := NormalizeGopkgInURL(c.in); got != c.norm {
			t.Fatalf("NormalizeGopkgInURL(%q)=%q want %q", c.in, got, c.norm)
		}
		if got := ExtractCanonicalPackageName(c.in); got != c.canon {
			t.Fatalf("ExtractCanonicalPackageName(%q)=%q want %q", c.in, got, c.canon)
		}
	}
}
