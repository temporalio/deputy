package compare

import (
	"testing"
)

func Test_NormalizeGopkgInURL_and_ExtractCanonical(t *testing.T) {
	cases := []struct{ in, norm, canon string }{
		{in: "gopkg.in/go-jose/go-jose.v2", norm: "github.com/go-jose/go-jose", canon: "github.com/go-jose/go-jose"},
		{in: "gopkg.in/yaml.v3", norm: "github.com/go-yaml/yaml", canon: "github.com/go-yaml/yaml"},
		{in: "gopkg.in/user/repo/subpkg.v2", norm: "github.com/user/repo/subpkg", canon: "github.com/user/repo/subpkg"},
		{in: "modernc.org/cc/v3", norm: "modernc.org/cc/v3", canon: "modernc.org/cc"},
		{in: "github.com/example/pkg/v10", norm: "github.com/example/pkg/v10", canon: "github.com/example/pkg"},
		{in: "github.com/example/pkg/v1", norm: "github.com/example/pkg/v1", canon: "github.com/example/pkg/v1"},
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
