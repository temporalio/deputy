package proxy

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"

	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	policyv1 "github.com/temporalio/deputy/gen/deputy/policy/v1"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/analysis/advisorysource"
	"github.com/temporalio/deputy/internal/analysis/osv"
	"github.com/temporalio/deputy/internal/policy"
	"google.golang.org/protobuf/proto"
)

// jwtClaimsToProto converts internal JWT claims to the proto JWTClaims type.
func jwtClaimsToProto(claims *JWTClaims) *policyv1.JWTClaims {
	if claims == nil {
		return &policyv1.JWTClaims{Anonymous: true}
	}
	pc := &policyv1.JWTClaims{
		Anonymous: false,
		Sub:       claims.Subject,
		Iss:       claims.Issuer,
		Aud:       claims.Audience,
		Exp:       claims.ExpiresAt,
		Iat:       claims.IssuedAt,
		Nbf:       claims.NotBefore,
		Jti:       claims.JWTID,
	}
	// Convert custom claims to string map (proto limitation)
	if len(claims.Custom) > 0 {
		pc.CustomClaims = make(map[string]string, len(claims.Custom))
		for k, v := range claims.Custom {
			pc.CustomClaims[k] = fmt.Sprint(v)
		}
	}
	return pc
}

// baseHandler contains the common fields and initialization logic shared by all
// ecosystem-specific proxy handlers.
type baseHandler struct {
	policies PolicyEvaluator
	proxy    *httputil.ReverseProxy
	lookups  handlerLookups
}

// handlerConfig specifies how to initialize a baseHandler for a specific ecosystem.
type handlerConfig struct {
	ecosystem    string
	osvEcosystem string // OSV ecosystem name (e.g., "Go", "npm", "PyPI", "RubyGems")
	upstream     string
	policies     PolicyEvaluator
	wantLicenses bool
	osvCache     OSVCache     // optional, uses global cache if nil
	licenseCache LicenseCache // optional, uses global cache if nil
}

// newBaseHandler creates a baseHandler with the common initialization logic.
func newBaseHandler(cfg handlerConfig) (*baseHandler, error) {
	u, err := url.Parse(cfg.upstream)
	if err != nil {
		return nil, fmt.Errorf("parse upstream %q: %w", cfg.upstream, err)
	}
	client := newUpstreamHTTPClient()

	// The proxy is long-lived, so build the advisory-source registry once at
	// handler construction: built-in OSV plus any configured plugin/service
	// sources. The per-package cache sits in front, so external sources are
	// consulted only on cache misses.
	sources := advisorysource.NewDefaultRegistry(context.Background(), osv.NewClient())

	// Use provided caches or fall back to defaults
	osvCache := getOSVCache(cfg.osvCache)
	licenseCache := getLicenseCache(cfg.licenseCache)

	h := &baseHandler{
		policies: cfg.policies,
		proxy:    newUpstreamReverseProxy(u, cfg.ecosystem, client.Transport),
		lookups: handlerLookups{
			advisorySources: sources,
			vulnLookup: func(ctx context.Context, name, version string) ([]osv.Vulnerability, error) {
				return cachedOSVLookupWithCache(ctx, sources, osvCache, cfg.osvEcosystem, name, version)
			},
		},
	}
	if cfg.wantLicenses {
		h.lookups.licenseLookup = func(ctx context.Context, name, version string) ([]string, error) {
			return cachedLicenseLookupWithCache(ctx, licenseCache, cfg.ecosystem, name, version)
		}
	}
	return h, nil
}

// requestInfo holds parsed information from an incoming proxy request.
type requestInfo struct {
	Name       string
	Version    string
	HasVersion bool
	Operation  string
	Ecosystem  string
	FileType   string // optional, used by Go proxy
	Filename   string // optional, used by PyPI
}

// buildPolicyInput constructs the typed policy input proto from request info.
// The input includes request metadata and optionally vulnerability/license data.
func (h *baseHandler) buildPolicyInput(ctx context.Context, info requestInfo, entrypoint policy.Entrypoint) proto.Message {
	version := info.Version
	if !info.HasVersion {
		version = unknownVersionPlaceholder
	}

	// Build the request proto
	req := &policyv1.ProxyRequest{
		Ecosystem: info.Ecosystem,
		Version:   version,
		Operation: info.Operation,
	}
	if info.Ecosystem == "go" {
		req.Module = info.Name
	} else {
		req.Package = info.Name
	}

	// Get JWT claims
	jwt := jwtClaimsToProto(JWTClaimsFromContext(ctx))

	// Get environment
	env := &policyv1.Environment{
		Command:    "proxy",
		Entrypoint: entrypoint.String(),
	}

	// Get vulnerabilities if version is known
	var vulns []*vulnerabilityv1.Finding
	var licenses []string
	if info.HasVersion {
		vulns = lookupVulnerabilities(ctx, h.lookups, info.Ecosystem, info.Name, info.Version)
		licenses = lookupLicenses(ctx, h.lookups, info.Name, info.Version)
	}

	// Build the pkg proto
	pkg := &dependencyv1.Package{
		Name:      info.Name,
		Version:   version,
		Ecosystem: info.Ecosystem,
		Licenses:  licenses,
	}

	// Return the appropriate typed input based on ecosystem
	switch info.Ecosystem {
	case "go":
		return &policyv1.GoArtifactRequestPolicyInput{
			Request:         req,
			Jwt:             jwt,
			Env:             env,
			Vulnerabilities: vulns,
			Pkg:             pkg,
		}
	case "npm":
		return &policyv1.NpmArtifactRequestPolicyInput{
			Request:         req,
			Jwt:             jwt,
			Env:             env,
			Vulnerabilities: vulns,
			Pkg:             pkg,
		}
	case "pypi":
		return &policyv1.PypiArtifactRequestPolicyInput{
			Request:         req,
			Jwt:             jwt,
			Env:             env,
			Vulnerabilities: vulns,
			Pkg:             pkg,
		}
	case "rubygems":
		return &policyv1.RubygemsArtifactRequestPolicyInput{
			Request:         req,
			Jwt:             jwt,
			Env:             env,
			Vulnerabilities: vulns,
			Pkg:             pkg,
		}
	default:
		// Fallback to Go input for unknown ecosystems
		return &policyv1.GoArtifactRequestPolicyInput{
			Request:         req,
			Jwt:             jwt,
			Env:             env,
			Vulnerabilities: vulns,
			Pkg:             pkg,
		}
	}
}

// serve handles the common pattern of policy evaluation and proxying.
func (h *baseHandler) serve(w http.ResponseWriter, r *http.Request, entrypoint policy.Entrypoint, info requestInfo, input proto.Message) {
	rawVersion := info.Version
	if !info.HasVersion {
		rawVersion = ""
	}
	serveWithPolicy(w, r, h.policies, entrypoint, input, blockMeta{
		Ecosystem: info.Ecosystem,
		Name:      info.Name,
		Version:   rawVersion,
		Operation: info.Operation,
	}, h.proxy)
}
