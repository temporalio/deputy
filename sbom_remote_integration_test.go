package main

import (
	"strings"
	"testing"
	"time"

	packageurl "github.com/package-url/packageurl-go"
)

// Table-driven remote fetch + scan tests to cover multiple PURL shapes.
func Test_goGitFetcher_FetchAndScan(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping remote fetch integration test in short mode")
	}
	cases := []struct {
		name   string
		purl   string
		expect []string // expected SPDX license IDs subset present in detected IDs
	}{
		{name: "github tag", purl: "pkg:github/sirupsen/logrus@v1.9.2", expect: []string{"MIT"}},
		{name: "github default branch", purl: "pkg:github/sirupsen/logrus", expect: []string{"MIT"}},
		{name: "golang github module tag", purl: "pkg:golang/github.com/sirupsen/logrus@v1.9.2", expect: []string{"MIT"}},
		{name: "golang module tag cobra", purl: "pkg:golang/github.com/spf13/cobra@v1.7.0", expect: []string{"Apache-2.0"}},
		{name: "github tag gin", purl: "pkg:github/gin-gonic/gin@v1.9.1", expect: []string{"MIT"}},
		{name: "github default go-getter", purl: "pkg:github/hashicorp/go-getter", expect: []string{"MPL-2.0"}},
		{name: "golang module tag go-getter", purl: "pkg:golang/github.com/hashicorp/go-getter@v1.7.0", expect: []string{"MPL-2.0"}},
		{name: "github default temporal server", purl: "pkg:github/temporalio/temporal", expect: []string{"MIT"}},
		{name: "github default temporal go sdk", purl: "pkg:github/temporalio/sdk-go", expect: []string{"MIT"}},
		{name: "github default temporal python sdk", purl: "pkg:github/temporalio/sdk-python", expect: []string{"MIT"}},
		{name: "github default temporal ruby sdk", purl: "pkg:github/temporalio/sdk-ruby", expect: []string{"MIT"}},
		{name: "github default temporal java sdk", purl: "pkg:github/temporalio/sdk-java", expect: []string{"Apache-2.0"}},
		{name: "github default temporal dotnet sdk", purl: "pkg:github/temporalio/sdk-dotnet", expect: []string{"MIT"}},
		{name: "github tag kubernetes client-go", purl: "pkg:github/kubernetes/client-go@v0.28.0", expect: []string{"Apache-2.0"}},
		{name: "github tag prometheus client_golang", purl: "pkg:github/prometheus/client_golang@v1.18.0", expect: []string{"Apache-2.0"}},
		{name: "github tag uber zap", purl: "pkg:github/uber-go/zap@v1.27.0", expect: []string{"MIT"}},
		{name: "github tag go-sql-driver/mysql", purl: "pkg:github/go-sql-driver/mysql@v1.7.1", expect: []string{"MPL-2.0"}},
		{name: "github tag google/uuid", purl: "pkg:github/google/uuid@v1.6.0", expect: []string{"BSD-3-Clause"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			p, err := packageurl.FromString(tc.purl)
			if err != nil {
				t.Fatalf("parse purl: %v", err)
			}
			f := &remoteFetcher{Timeout: 30 * time.Second}
			fs, root, err := f.Fetch(ctx, p)
			if err != nil {
				t.Fatalf("fetch: %v", err)
			}
			ids := scanBillyForLicenseIDs(fs, root)
			if len(ids) == 0 {
				t.Fatalf("expected license IDs for %q, got none", tc.purl)
			}
			if len(tc.expect) > 0 && !containsAllFold(ids, tc.expect) {
				t.Fatalf("expected IDs %v to contain all of %v for %q", ids, tc.expect, tc.purl)
			}
		})
	}
}

func containsAllFold(have []string, want []string) bool {
	set := map[string]struct{}{}
	for _, s := range have {
		set[strings.ToUpper(strings.TrimSpace(s))] = struct{}{}
	}
	for _, w := range want {
		if _, ok := set[strings.ToUpper(strings.TrimSpace(w))]; !ok {
			return false
		}
	}
	return true
}
