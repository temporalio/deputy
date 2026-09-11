package osv

import (
	"errors"
	"slices"
	"testing"
)

func TestIsNotFoundError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil",
			err:  nil,
		},
		{
			name: "osv 404",
			err:  errors.New(`client error: status="404 Not Found" body={"code":5,"message":"Bug not found."}`),
			want: true,
		},
		{
			name: "grpc code 5 not found body",
			err:  errors.New(`client error: status="400 Bad Request" body={"code":5,"message":"Bug not found."}`),
			want: true,
		},
		{
			name: "invalid query",
			err:  errors.New(`client error: status="400 Bad Request" body={"code":3,"message":"Invalid query."}`),
		},
		{
			name: "network error mentioning not found",
			err:  errors.New("lookup osv.dev: no such host; cache file not found"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsNotFoundError(tt.err); got != tt.want {
				t.Fatalf("IsNotFoundError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

// TestNotFoundAliases covers the one place OSV names the records that replaced a
// withdrawn ID: the not-found response body. The querybatch stub that reported
// the missing ID carries only an id and a modified timestamp, so if these IDs
// cannot be read back out of the error there is nothing to recover through.
func TestNotFoundAliases(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want []string
	}{
		{
			name: "nil error",
		},
		{
			name: "not a not-found error",
			err:  errors.New(`client error: status="400 Bad Request" body={"code":3,"message":"Invalid query."}`),
		},
		{
			name: "transport failure is not a not-found",
			err:  errors.New("max retries exceeded: attempt 4: request failed: dial tcp: i/o timeout"),
		},
		{
			// The live response for GO-2026-6255, verbatim.
			name: "withdrawn record names its aliases",
			err:  errors.New(`client error: status="404 Not Found" body={"code":5,"message":"Vulnerability not found, but the following aliases were: CVE-2026-61711 GHSA-7236-3392-c5c6"}`),
			want: []string{"CVE-2026-61711", "GHSA-7236-3392-c5c6"},
		},
		{
			name: "deleted record names no aliases",
			err:  errors.New(`client error: status="404 Not Found" body={"code":5,"message":"Bug not found."}`),
		},
		{
			name: "wrapped error still yields aliases",
			err:  errors.New(`expand vulnerability GO-2026-6255: client error: status="404 Not Found" body={"code":5,"message":"Vulnerability not found, but the following aliases were: GHSA-7236-3392-c5c6"}`),
			want: []string{"GHSA-7236-3392-c5c6"},
		},
		{
			name: "unparseable body falls back to scanning the text",
			err:  errors.New(`client error: status="404 Not Found" body=Vulnerability not found, but the following aliases were: PYSEC-2026-1 RUSTSEC-2026-0001`),
			want: []string{"PYSEC-2026-1", "RUSTSEC-2026-0001"},
		},
		{
			name: "repeated alias is reported once",
			err:  errors.New(`client error: status="404 Not Found" body={"code":5,"message":"aliases were: CVE-2026-1 cve-2026-1 CVE-2026-1"}`),
			want: []string{"CVE-2026-1"},
		},
		{
			name: "hyphenated prose is not an identifier",
			err:  errors.New(`client error: status="404 Not Found" body={"code":5,"message":"NOT-FOUND: no such record"}`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NotFoundAliases(tt.err)
			if !slices.Equal(got, tt.want) {
				t.Fatalf("NotFoundAliases() = %v, want %v", got, tt.want)
			}
		})
	}
}
