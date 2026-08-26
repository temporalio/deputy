package osv

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"osv.dev/bindings/go/api"
)

// notFoundErr renders the error the osv.dev client returns for a withdrawn
// record: formatted response text rather than a typed status, naming the
// aliases that do still exist. Deputy only ever sees these IDs here, because the
// querybatch stub that reported the missing ID carries just an id and a modified
// timestamp.
func notFoundErr(aliases ...string) error {
	if len(aliases) == 0 {
		return errors.New(`client error: status="404 Not Found" body={"code":5,"message":"Bug not found."}`)
	}
	return errors.New(`client error: status="404 Not Found" body={"code":5,"message":"Vulnerability not found, but the following aliases were: ` +
		strings.Join(aliases, " ") + `"}`)
}

// affectedRecord builds an OSV record that reports pkgName as affected at every
// version, so a test asserts on which advisory survived rather than on version
// arithmetic.
func affectedRecord(id, pkgName string) *osvschema.Vulnerability {
	return &osvschema.Vulnerability{
		Id:      id,
		Summary: id + " summary",
		Affected: []*osvschema.Affected{{
			Package: &osvschema.Package{Name: pkgName, Ecosystem: "Go"},
			Ranges: []*osvschema.Range{{
				Type:   osvschema.Range_SEMVER,
				Events: []*osvschema.Event{{Introduced: "0"}},
			}},
		}},
	}
}

// scriptedClient answers a batch query from a per-package advisory list and
// answers each expansion from a scripted table, so a test can make one advisory
// fail the way OSV actually fails it while the rest keep resolving.
type scriptedClient struct {
	// batch maps a queried package name to the advisory IDs OSV reports for it.
	batch map[string][]string
	// records maps an advisory ID to the record GetVulnByID returns.
	records map[string]*osvschema.Vulnerability
	// failures maps an advisory ID to the error GetVulnByID returns instead.
	failures map[string]error
}

func (c *scriptedClient) QueryBatch(_ context.Context, queries []*api.Query) (*api.BatchVulnerabilityList, error) {
	results := make([]*api.VulnerabilityList, 0, len(queries))
	for _, q := range queries {
		list := &api.VulnerabilityList{}
		for _, id := range c.batch[q.GetPackage().GetName()] {
			list.Vulns = append(list.Vulns, &osvschema.Vulnerability{Id: id})
		}
		results = append(results, list)
	}
	return &api.BatchVulnerabilityList{Results: results}, nil
}

func (c *scriptedClient) GetVulnByID(_ context.Context, id string) (*osvschema.Vulnerability, error) {
	if err, ok := c.failures[id]; ok {
		return nil, err
	}
	if rec, ok := c.records[id]; ok {
		return rec, nil
	}
	return nil, notFoundErr()
}

// TestQueryRaw_UnresolvedAdvisories covers what happens when the second OSV call
// disagrees with the first: the batch query attributes an advisory to a package,
// and expanding it fails. A withdrawn record must cost only its own finding, a
// transport failure must still fail the scan, and neither may leave the caller
// with a result that reads as clean.
func TestQueryRaw_UnresolvedAdvisories(t *testing.T) {
	const (
		buildkit = "github.com/moby/buildkit"
		other    = "github.com/example/other"
		// The real IDs from issue #320.
		withdrawn = "GO-2026-6255"
		ghsaAlias = "GHSA-7236-3392-c5c6"
		cveAlias  = "CVE-2026-61711"
	)

	tests := []struct {
		name string
		// pkgs defaults to buildkit alone when empty.
		pkgs   []PkgInput
		client *scriptedClient
		// wantErrContains, when set, implies wantErr and pins the substring that
		// identifies which lookup failed. An expansion error that only says
		// "not found" would be the bug this asserts against.
		wantErrContains string
		wantErr         bool
		wantAdvisories  []string
		wantUnresolved  []UnresolvedAdvisory
	}{
		{
			// The reported bug: one withdrawn record used to abort everything.
			name: "withdrawn advisory does not cost other packages their findings",
			pkgs: []PkgInput{
				{QueryKey: QueryKey{Name: buildkit, Version: "v0.30.0", Ecosystem: "Go"}},
				{QueryKey: QueryKey{Name: other, Version: "v1.0.0", Ecosystem: "Go"}},
			},
			client: &scriptedClient{
				batch: map[string][]string{
					buildkit: {withdrawn},
					other:    {"GHSA-live-0000-0001"},
				},
				failures: map[string]error{withdrawn: notFoundErr()},
				records: map[string]*osvschema.Vulnerability{
					"GHSA-live-0000-0001": affectedRecord("GHSA-live-0000-0001", other),
				},
			},
			wantAdvisories: []string{"GHSA-live-0000-0001"},
			wantUnresolved: []UnresolvedAdvisory{{
				ID:      withdrawn,
				Package: buildkit + "@v0.30.0",
				Reason:  unresolvedNotFoundReason,
			}},
		},
		{
			name: "unresolved advisory is reported, not dropped",
			client: &scriptedClient{
				batch:    map[string][]string{buildkit: {withdrawn}},
				failures: map[string]error{withdrawn: notFoundErr()},
			},
			wantUnresolved: []UnresolvedAdvisory{{
				ID:      withdrawn,
				Package: buildkit + "@v0.30.0",
				Reason:  unresolvedNotFoundReason,
			}},
		},
		{
			// The 404 body names live records, so the finding is recovered
			// under the ID a reader can actually look up.
			name: "alias named by the 404 recovers the record",
			client: &scriptedClient{
				batch:    map[string][]string{buildkit: {withdrawn}},
				failures: map[string]error{withdrawn: notFoundErr(cveAlias, ghsaAlias)},
				records: map[string]*osvschema.Vulnerability{
					ghsaAlias: affectedRecord(ghsaAlias, buildkit),
					cveAlias:  affectedRecord(cveAlias, buildkit),
				},
			},
			// GHSA first: SeverityAliasOrder prefers the reviewed database.
			wantAdvisories: []string{ghsaAlias},
		},
		{
			name: "alias that also 404s leaves the advisory unresolved",
			client: &scriptedClient{
				batch: map[string][]string{buildkit: {withdrawn}},
				failures: map[string]error{
					withdrawn: notFoundErr(ghsaAlias),
					ghsaAlias: notFoundErr(),
				},
			},
			wantUnresolved: []UnresolvedAdvisory{{
				ID:      withdrawn,
				Package: buildkit + "@v0.30.0",
				Reason:  unresolvedNotFoundReason,
			}},
		},
		{
			// A 404 on one alias says nothing about the next one, so the search
			// keeps going and the finding survives under the ID that resolved.
			name: "not-found alias is skipped and recovery continues",
			client: &scriptedClient{
				batch: map[string][]string{buildkit: {withdrawn}},
				failures: map[string]error{
					withdrawn: notFoundErr(cveAlias, ghsaAlias),
					// Tried first, since SeverityAliasOrder prefers GHSA.
					ghsaAlias: notFoundErr(),
				},
				records: map[string]*osvschema.Vulnerability{
					cveAlias: affectedRecord(cveAlias, buildkit),
				},
			},
			wantAdvisories: []string{cveAlias},
		},
		{
			// The defect this pins: a network blip on the alias used to be
			// discarded, the original 404 returned, and an expansion we never
			// completed filed as a withdrawn record on a successful scan.
			name: "transient alias failure stays fatal instead of reading as withdrawn",
			client: &scriptedClient{
				batch: map[string][]string{buildkit: {withdrawn}},
				failures: map[string]error{
					withdrawn: notFoundErr(ghsaAlias),
					ghsaAlias: errors.New("max retries exceeded: attempt 4: request failed: dial tcp: i/o timeout"),
				},
			},
			wantErrContains: "resolve alias " + ghsaAlias + " of " + withdrawn,
		},
		{
			// An exhausted 5xx retry is the same class of ignorance as a
			// timeout: OSV never told us whether the alias replaces the record.
			name: "exhausted alias retry stays fatal",
			client: &scriptedClient{
				batch: map[string][]string{buildkit: {withdrawn}},
				failures: map[string]error{
					withdrawn: notFoundErr(ghsaAlias),
					ghsaAlias: errors.New(`max retries exceeded: server error: status="503 Service Unavailable" body=busy`),
				},
			},
			wantErrContains: "resolve alias " + ghsaAlias + " of " + withdrawn,
		},
		{
			// A completed recovery answers the question the failed alias left
			// open, so the kept error must not override it.
			name: "later alias recovers despite an earlier transient failure",
			client: &scriptedClient{
				batch: map[string][]string{buildkit: {withdrawn}},
				failures: map[string]error{
					withdrawn: notFoundErr(cveAlias, ghsaAlias),
					ghsaAlias: errors.New("max retries exceeded: attempt 4: request failed: dial tcp: i/o timeout"),
				},
				records: map[string]*osvschema.Vulnerability{
					cveAlias: affectedRecord(cveAlias, buildkit),
				},
			},
			wantAdvisories: []string{cveAlias},
		},
		{
			// The alias list is read out of response text, so a record about
			// some other package is a misread and must not be reported here.
			name: "alias about a different package is not accepted",
			client: &scriptedClient{
				batch:    map[string][]string{buildkit: {withdrawn}},
				failures: map[string]error{withdrawn: notFoundErr(ghsaAlias)},
				records: map[string]*osvschema.Vulnerability{
					ghsaAlias: affectedRecord(ghsaAlias, other),
				},
			},
			wantUnresolved: []UnresolvedAdvisory{{
				ID:      withdrawn,
				Package: buildkit + "@v0.30.0",
				Reason:  unresolvedNotFoundReason,
			}},
		},
		{
			// OSV lists a withdrawn ID next to the live alias that replaced it,
			// so recovery can land on a record the batch already named.
			name: "recovered record already in the batch is not reported twice",
			client: &scriptedClient{
				batch:    map[string][]string{buildkit: {withdrawn, ghsaAlias}},
				failures: map[string]error{withdrawn: notFoundErr(ghsaAlias)},
				records: map[string]*osvschema.Vulnerability{
					ghsaAlias: affectedRecord(ghsaAlias, buildkit),
				},
			},
			wantAdvisories: []string{ghsaAlias},
		},
		{
			// A network blip is not a withdrawn record: it will not reproduce,
			// so a result missing advisories because of it must not be served.
			name: "transport failure stays fatal",
			client: &scriptedClient{
				batch:    map[string][]string{buildkit: {withdrawn}},
				failures: map[string]error{withdrawn: errors.New("max retries exceeded: attempt 4: request failed: dial tcp: i/o timeout")},
			},
			wantErr: true,
		},
		{
			name: "server error stays fatal",
			client: &scriptedClient{
				batch:    map[string][]string{buildkit: {withdrawn}},
				failures: map[string]error{withdrawn: errors.New(`max retries exceeded: server error: status="503 Service Unavailable" body=busy`)},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetDiskCache(t)
			pkgs := tt.pkgs
			if len(pkgs) == 0 {
				pkgs = []PkgInput{{QueryKey: QueryKey{Name: buildkit, Version: "v0.30.0", Ecosystem: "Go"}}}
			}

			vulns, unresolved, err := QueryRaw(t.Context(), tt.client, pkgs)
			if tt.wantErr || tt.wantErrContains != "" {
				if err == nil {
					t.Fatalf("QueryRaw() error = nil, want an error (findings = %d, unresolved = %+v)", len(vulns), unresolved)
				}
				if tt.wantErrContains != "" && !strings.Contains(err.Error(), tt.wantErrContains) {
					t.Fatalf("QueryRaw() error = %v, want it to mention %q", err, tt.wantErrContains)
				}
				if len(unresolved) != 0 {
					t.Fatalf("unresolved = %+v, want none: a failed expansion is not a withdrawn advisory", unresolved)
				}
				return
			}
			if err != nil {
				t.Fatalf("QueryRaw() error = %v, want nil", err)
			}

			gotAdvisories := make([]string, 0, len(vulns))
			for _, v := range vulns {
				gotAdvisories = append(gotAdvisories, v.ID)
			}
			slices.Sort(gotAdvisories)
			want := slices.Clone(tt.wantAdvisories)
			slices.Sort(want)
			if !slices.Equal(gotAdvisories, want) {
				t.Errorf("advisories in findings = %v, want %v", gotAdvisories, want)
			}

			if !slices.Equal(unresolved, tt.wantUnresolved) {
				t.Errorf("unresolved = %+v, want %+v", unresolved, tt.wantUnresolved)
			}
		})
	}
}

// TestUnresolvedAdvisoryWarning pins the text the scan report shows, because it
// is the only thing that stops an incomplete scan from reading as a clean one.
func TestUnresolvedAdvisoryWarning(t *testing.T) {
	tests := []struct {
		name string
		in   []UnresolvedAdvisory
		want []string
	}{
		{
			name: "no unresolved advisories adds no warning",
		},
		{
			name: "warning names the advisory, the package, and the omission",
			in: []UnresolvedAdvisory{{
				ID:      "GO-2026-6255",
				Package: "github.com/moby/buildkit@v0.30.0",
				Reason:  unresolvedNotFoundReason,
			}},
			want: []string{
				"osv: advisory GO-2026-6255 reported for github.com/moby/buildkit@v0.30.0 is missing from this report: " +
					"OSV returned not found for the record, and no alias it named resolved",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := AdvisoryWarnings(tt.in); !slices.Equal(got, tt.want) {
				t.Fatalf("AdvisoryWarnings() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestQueryRaw_CancelledScanIsNotAWithdrawnAdvisory guards the seam where the
// two policies meet: cancellation surfaces through the same call as a 404, and
// mistaking it for a withdrawn record would turn an abandoned scan into a
// report that looks almost complete.
//
// The cases cover both shapes a cancellation actually arrives in. The osv.dev
// client returns context.DeadlineExceeded bare but runs context.Canceled
// through its retry path, which formats it into "max retries exceeded", so
// asserting only on the bare value would leave the shape real callers see
// untested.
func TestQueryRaw_CancelledScanIsNotAWithdrawnAdvisory(t *testing.T) {
	const (
		buildkit  = "github.com/moby/buildkit"
		withdrawn = "GO-2026-6255"
	)

	tests := []struct {
		name string
		err  error
	}{
		{
			name: "bare context error",
			err:  context.Canceled,
		},
		{
			name: "deadline exceeded",
			err:  context.DeadlineExceeded,
		},
		{
			// The shape the real client produces for a cancelled request.
			name: "wrapped by the client's retry loop",
			err:  fmt.Errorf(`max retries exceeded: attempt 1: request failed: Get "https://api.osv.dev/v1/vulns/%s": %w`, withdrawn, context.Canceled),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetDiskCache(t)
			ctx, cancel := context.WithCancel(t.Context())
			cancel()

			client := &scriptedClient{
				batch:    map[string][]string{buildkit: {withdrawn}},
				failures: map[string]error{withdrawn: tt.err},
			}
			_, unresolved, err := QueryRaw(ctx, client, []PkgInput{
				{QueryKey: QueryKey{Name: buildkit, Version: "v0.30.0", Ecosystem: "Go"}},
			})
			if err == nil {
				t.Fatalf("QueryRaw() error = nil, want a cancellation error (unresolved = %+v)", unresolved)
			}
			if len(unresolved) != 0 {
				t.Fatalf("unresolved = %+v, want none: a cancelled scan is not a withdrawn advisory", unresolved)
			}
		})
	}
}

// cancelDuringRecoveryClient 404s the requested advisory with a live alias, then
// cancels the scan before the alias can be fetched. This is the one ordering
// where the not-found classification is already settled and cancellation
// arrives afterward, so only the context check inside the recovery loop keeps
// the advisory from being filed as withdrawn.
type cancelDuringRecoveryClient struct {
	advisoryID string
	alias      string
	cancel     context.CancelFunc
}

func (c *cancelDuringRecoveryClient) QueryBatch(_ context.Context, queries []*api.Query) (*api.BatchVulnerabilityList, error) {
	results := make([]*api.VulnerabilityList, 0, len(queries))
	for range queries {
		results = append(results, &api.VulnerabilityList{
			Vulns: []*osvschema.Vulnerability{{Id: c.advisoryID}},
		})
	}
	return &api.BatchVulnerabilityList{Results: results}, nil
}

func (c *cancelDuringRecoveryClient) GetVulnByID(_ context.Context, id string) (*osvschema.Vulnerability, error) {
	if id == c.advisoryID {
		// The 404 lands first, then the scan is cancelled.
		c.cancel()
		return nil, notFoundErr(c.alias)
	}
	return nil, errors.New("alias lookup should not run on a cancelled scan")
}

// TestQueryRaw_CancelledDuringAliasRecoveryIsNotUnresolved pins the narrow race
// the recovery loop's context check exists for: a 404 that names a live alias,
// followed by cancellation. Without the check the alias fetch fails, the
// original not-found error is returned, and an abandoned scan reports the
// advisory as withdrawn instead of failing.
func TestQueryRaw_CancelledDuringAliasRecoveryIsNotUnresolved(t *testing.T) {
	resetDiskCache(t)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	client := &cancelDuringRecoveryClient{
		advisoryID: "GO-2026-6255",
		alias:      "GHSA-7236-3392-c5c6",
		cancel:     cancel,
	}
	_, unresolved, err := QueryRaw(ctx, client, []PkgInput{
		{QueryKey: QueryKey{Name: "github.com/moby/buildkit", Version: "v0.30.0", Ecosystem: "Go"}},
	})
	if err == nil {
		t.Fatalf("QueryRaw() error = nil, want a cancellation error (unresolved = %+v)", unresolved)
	}
	if len(unresolved) != 0 {
		t.Fatalf("unresolved = %+v, want none: cancellation mid-recovery is not a withdrawn advisory", unresolved)
	}
}

// cancelInsideAliasLookupClient 404s the requested advisory with an alias, then
// cancels the scan from inside the alias lookup and answers it with a 404 of its
// own. The recovery loop's own context check has already run by then, and a
// not-found alias is a normal dead end rather than an error worth keeping, so
// nothing is left holding the cancellation except the recheck that runs before
// the advisory is classified.
type cancelInsideAliasLookupClient struct {
	advisoryID string
	alias      string
	cancel     context.CancelFunc
}

func (c *cancelInsideAliasLookupClient) QueryBatch(_ context.Context, queries []*api.Query) (*api.BatchVulnerabilityList, error) {
	results := make([]*api.VulnerabilityList, 0, len(queries))
	for range queries {
		results = append(results, &api.VulnerabilityList{
			Vulns: []*osvschema.Vulnerability{{Id: c.advisoryID}},
		})
	}
	return &api.BatchVulnerabilityList{Results: results}, nil
}

func (c *cancelInsideAliasLookupClient) GetVulnByID(_ context.Context, id string) (*osvschema.Vulnerability, error) {
	if id == c.advisoryID {
		return nil, notFoundErr(c.alias)
	}
	// The scan is abandoned while this last alias lookup is in flight.
	c.cancel()
	return nil, notFoundErr()
}

// TestQueryRaw_CancelledDuringLastAliasLookupIsNotUnresolved covers the other
// half of the cancellation race: the alias lookup itself is what the
// cancellation lands on. Every alias has been tried and none resolved, so the
// original not-found error is about to be handed back, which would report an
// abandoned scan as a withdrawn advisory on an otherwise successful run.
func TestQueryRaw_CancelledDuringLastAliasLookupIsNotUnresolved(t *testing.T) {
	resetDiskCache(t)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	client := &cancelInsideAliasLookupClient{
		advisoryID: "GO-2026-6255",
		alias:      "GHSA-7236-3392-c5c6",
		cancel:     cancel,
	}
	_, unresolved, err := QueryRaw(ctx, client, []PkgInput{
		{QueryKey: QueryKey{Name: "github.com/moby/buildkit", Version: "v0.30.0", Ecosystem: "Go"}},
	})
	if err == nil {
		t.Fatalf("QueryRaw() error = nil, want a cancellation error (unresolved = %+v)", unresolved)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("QueryRaw() error = %v, want a context.Canceled", err)
	}
	if len(unresolved) != 0 {
		t.Fatalf("unresolved = %+v, want none: cancellation on the last alias lookup is not a withdrawal", unresolved)
	}
}
