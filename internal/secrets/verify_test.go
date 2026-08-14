package secrets

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

// probeSecretTypes is the universe of secret types used to route each
// registered verifier to a type it handles. It mirrors the SecretType
// constants in detector.go; if a new verifier matches none of these, the test
// below fails loudly instead of silently skipping it, so an incomplete list
// cannot hide a verifier.
var probeSecretTypes = []SecretType{
	TypeGCPAPIKey, TypeGCPServiceAccountKey, TypeRubyGemsAPIKey,
	TypeAWSAccessKey, TypeAWSSecretKey, TypeGitHubToken, TypeGitHubFineGrain,
	TypeGenericAPIKey, TypePrivateKey, TypeJWT, TypeSlackToken, TypeStripeKey,
	TypeSendGridKey, TypeNpmToken, TypePyPIToken, TypeDiscordToken,
	TypeTelegramToken, TypeHerokuAPIKey, TypeMailgunKey, TypeTwilioKey,
	TypeHighEntropy, TypeSensitiveEnvVar, TypeSlackWebhook, TypeTerraformToken,
	TypeCloudflareAPIKey, TypeDatadogAPIKey, TypeLinearAPIKey, TypeOpenAIKey,
	TypeAnthropicKey, TypeAzureSASToken, TypeGitLabToken, TypeBitbucketToken,
	TypeDigitalOceanToken,
}

// bodyCanary marks the parts of a staged upstream response that no verifier
// is entitled to republish: fields its response struct decodes but never
// emits, fields it does not model at all, and content trailing the JSON
// document. Values a verifier is meant to surface (logins, e-mail addresses,
// scopes) are deliberately realistic instead, so the assertion distinguishes
// "decoded the documented identity" from "echoed whatever the endpoint sent".
const bodyCanary = "RESPONSE-BODY-CANARY-2f8c1d"

// verifierCanary is one staged upstream exchange for a single verifier: the
// credential handed to Verify, the response the transport serves back, and
// the VerificationResult fields the verifier must derive from it.
type verifierCanary struct {
	// name labels the scenario in subtest output.
	name string
	// secret is the credential passed to Verify. It is provider-shaped so
	// format-checking verifiers reach their accepting branch, and unique per
	// scenario so an echo of it into the result is unambiguous.
	secret string
	// status is the HTTP status served to the verifier.
	status int
	// header is served with the response. Verifiers that read metadata out of
	// headers (GitHub's X-OAuth-Scopes) need it populated.
	header map[string]string
	// body is the response body served to the verifier. It must parse as the
	// provider payload the verifier expects, otherwise the verifier falls back
	// to a status-only branch and never touches the body at all.
	body string
	// wantStatus is the VerificationStatus the verifier must report. Pinning it
	// is what proves the body-parsing branch actually ran: a payload the
	// verifier cannot parse degrades to a status fallback, which would leave
	// the leak assertions vacuously satisfied.
	wantStatus VerificationStatus
	// wantIdentity is the identity the verifier must have decoded out of body.
	// Empty means the verifier reports none.
	wantIdentity string
	// wantScopes are the scopes the verifier must report. Nil means none.
	wantScopes []string
}

// verifierCanaries stages, per registered verifier name, the upstream
// exchanges TestVerifiersDoNotLeakResponseBody drives it through. Each body is
// provider-appropriate so the verifier's own parser accepts it and the
// result-populating branch runs; a generic blob would fail every decode and
// leave the code that copies decoded fields into a VerificationResult
// unreached. Multiple entries cover verifiers with more than one
// body-dependent branch.
func verifierCanaries() map[string][]verifierCanary {
	return map[string][]verifierCanary{
		"github": {{
			name:         "authenticated_user",
			secret:       "ghp_canarygithubtoken000000000000000",
			status:       http.StatusOK,
			header:       map[string]string{"X-OAuth-Scopes": "repo, read:org"},
			body:         fmt.Sprintf(`{"login":"octocat","id":583231,"type":"User","email":"%[1]s@example.com","node_id":"%[1]s"} %[1]s`, bodyCanary),
			wantStatus:   StatusValid,
			wantIdentity: "octocat",
			wantScopes:   []string{"repo", "read:org"},
		}},
		"gitlab": {{
			name:         "authenticated_user",
			secret:       "glpat-canarygitlabtoken0",
			status:       http.StatusOK,
			body:         fmt.Sprintf(`{"username":"octocat","name":"Octo Cat","id":42,"bio":"%[1]s","web_url":"%[1]s"} %[1]s`, bodyCanary),
			wantStatus:   StatusValid,
			wantIdentity: "octocat",
		}},
		"aws": {
			{
				// AKIA plus sixteen characters: the exact shape the verifier
				// accepts, so it reaches its non-rejecting branch.
				name:       "well_formed_access_key",
				secret:     "AKIACANARY0000000001",
				status:     http.StatusOK,
				body:       fmt.Sprintf(`{"note":"%[1]s"} %[1]s`, bodyCanary),
				wantStatus: StatusUnknown,
			},
			{
				name:       "malformed_access_key",
				secret:     "canary-aws-wrong-shape",
				status:     http.StatusOK,
				body:       fmt.Sprintf(`{"note":"%[1]s"} %[1]s`, bodyCanary),
				wantStatus: StatusInvalid,
			},
		},
		"slack": {
			{
				name:         "authenticated_user",
				secret:       "xoxb-canary-slack-authenticated",
				status:       http.StatusOK,
				body:         fmt.Sprintf(`{"ok":true,"user":"octocat","team":"canaries","url":"%[1]s","user_id":"%[1]s","bot_id":"%[1]s"} %[1]s`, bodyCanary),
				wantStatus:   StatusValid,
				wantIdentity: "octocat@canaries",
			},
			{
				// A documented Slack error code: the verifier compares it
				// against known literals, so surfacing it is safe.
				name:       "documented_error_code",
				secret:     "xoxb-canary-slack-revoked",
				status:     http.StatusOK,
				body:       fmt.Sprintf(`{"ok":false,"error":"token_revoked","detail":"%[1]s"}`, bodyCanary),
				wantStatus: StatusInvalid,
			},
			{
				// The disclosure path: an endpoint that answers with free-form
				// text where a code belongs. Copying it verbatim republishes
				// whatever the endpoint chose to send, up to the credential.
				name:       "free_form_error_text",
				secret:     "xoxb-canary-slack-hostile",
				status:     http.StatusOK,
				body:       fmt.Sprintf(`{"ok":false,"error":"%[1]s carrying xoxb-canary-slack-hostile"}`, bodyCanary),
				wantStatus: StatusError,
			},
			{
				// Slack is the one verifier that decodes the body regardless of
				// status, so an unparseable body reaches its decode-error path.
				name:       "unparseable_body",
				secret:     "xoxb-canary-slack-garbage",
				status:     http.StatusInternalServerError,
				body:       fmt.Sprintf("Token xoxb-canary-slack-garbage is expired %s", bodyCanary),
				wantStatus: StatusError,
			},
		},
		"stripe": {{
			name:       "test_mode_key",
			secret:     "sk_test_canarystripekey",
			status:     http.StatusOK,
			body:       fmt.Sprintf(`{"object":"balance","livemode":false,"available":[{"amount":0}],"note":"%[1]s"} %[1]s`, bodyCanary),
			wantStatus: StatusValid,
		}},
		"sendgrid": {{
			name:       "scoped_key",
			secret:     "SG.canarysendgridkey.canarysendgridsecret",
			status:     http.StatusOK,
			body:       fmt.Sprintf(`{"scopes":["mail.send","alerts.read"],"errors":[{"message":"%[1]s"}]} %[1]s`, bodyCanary),
			wantStatus: StatusValid,
			wantScopes: []string{"mail.send", "alerts.read"},
		}},
		"npm": {{
			// npm decodes email into its response struct but must not emit it.
			name:         "authenticated_user",
			secret:       "npm_canarynpmtoken0000000000000000000000",
			status:       http.StatusOK,
			body:         fmt.Sprintf(`{"name":"octocat","email":"%[1]s@example.com","tfa":"%[1]s"} %[1]s`, bodyCanary),
			wantStatus:   StatusValid,
			wantIdentity: "octocat",
		}},
		"openai": {{
			name:       "model_list_access",
			secret:     "sk-canaryopenaikey00000000000000000000",
			status:     http.StatusOK,
			body:       fmt.Sprintf(`{"object":"list","data":[{"id":"%[1]s"}]} %[1]s`, bodyCanary),
			wantStatus: StatusValid,
		}},
		"anthropic": {{
			// Anthropic drains the body for connection reuse; draining must not
			// become reading it into the result.
			name:       "messages_accepted",
			secret:     "sk-ant-canaryanthropickey00000000000",
			status:     http.StatusOK,
			body:       fmt.Sprintf(`{"id":"%[1]s","content":[{"type":"text","text":"%[1]s"}]} %[1]s`, bodyCanary),
			wantStatus: StatusValid,
		}},
		"digitalocean": {{
			name:         "account_details",
			secret:       "dop_v1_canarydigitaloceantoken",
			status:       http.StatusOK,
			body:         fmt.Sprintf(`{"account":{"email":"octocat@example.com","uuid":"%[1]s","droplet_limit":25},"meta":"%[1]s"} %[1]s`, bodyCanary),
			wantStatus:   StatusValid,
			wantIdentity: "octocat@example.com",
		}},
		"terraform": {{
			// Terraform Cloud decodes email but must only emit the username.
			name:         "account_details",
			secret:       "canaryterraform.atlasv1.canaryterraformtoken",
			status:       http.StatusOK,
			body:         fmt.Sprintf(`{"data":{"id":"%[1]s","attributes":{"username":"octocat","email":"%[1]s@example.com"}}} %[1]s`, bodyCanary),
			wantStatus:   StatusValid,
			wantIdentity: "octocat",
		}},
		"linear": {{
			name:         "graphql_viewer",
			secret:       "lin_api_canarylinearkey",
			status:       http.StatusOK,
			body:         fmt.Sprintf(`{"data":{"viewer":{"id":"%[1]s","name":"Octo Cat","email":"octocat@example.com"}},"extensions":{"trace":"%[1]s"}} %[1]s`, bodyCanary),
			wantStatus:   StatusValid,
			wantIdentity: "octocat@example.com",
		}},
		"pypi": {
			{
				name:       "well_formed_token",
				secret:     "pypi-canarypypitoken",
				status:     http.StatusOK,
				body:       fmt.Sprintf(`{"note":"%[1]s"} %[1]s`, bodyCanary),
				wantStatus: StatusUnknown,
			},
			{
				name:       "malformed_token",
				secret:     "canary-pypi-wrong-prefix",
				status:     http.StatusOK,
				body:       fmt.Sprintf(`{"note":"%[1]s"} %[1]s`, bodyCanary),
				wantStatus: StatusInvalid,
			},
		},
		"datadog": {
			{
				name:       "validated_key",
				secret:     "canarydatadogapikey00000000000000",
				status:     http.StatusOK,
				body:       fmt.Sprintf(`{"valid":true,"errors":["%[1]s"]} %[1]s`, bodyCanary),
				wantStatus: StatusValid,
			},
			{
				name:       "rejected_key",
				secret:     "canarydatadogapikeyrejected000000",
				status:     http.StatusOK,
				body:       fmt.Sprintf(`{"valid":false,"errors":["%[1]s"]} %[1]s`, bodyCanary),
				wantStatus: StatusInvalid,
			},
		},
	}
}

// canaryVerifier returns the registered verifier called name, backed by a
// private verification engine whose HTTP transport answers every request with
// exchange. Verifiers share their engine's client, so each scenario gets its
// own engine rather than mutating one shared transport, which lets the
// subtests run in parallel without racing.
func canaryVerifier(t *testing.T, name string, exchange verifierCanary) Verifier {
	t.Helper()

	engine := NewVerificationEngine(&VerificationConfig{Timeout: time.Second})
	engine.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		header := make(http.Header, len(exchange.header))
		for key, value := range exchange.header {
			header.Set(key, value)
		}
		return &http.Response{
			StatusCode: exchange.status,
			Body:       io.NopCloser(strings.NewReader(exchange.body)),
			Header:     header,
		}, nil
	})

	for _, verifier := range engine.verifiers {
		if verifier.Name() == name {
			return verifier
		}
	}
	t.Fatalf("no verifier named %s is registered", name)
	return nil
}

// TestVerifiersDoNotLeakResponseBody pins the credential-disclosure invariant
// for every registered verifier, not just GitHub: content an upstream endpoint
// controls must never be republished in a VerificationResult, because a
// hostile, spoofed or misconfigured host can reflect the credential straight
// back in a response field.
//
// The corpus is engine.verifiers crossed with verifierCanaries, checked in
// both directions, so a newly registered verifier is covered automatically and
// a stale canary cannot linger. Each canary body is provider-appropriate: the
// verifier's own decoder accepts it, so the branch that copies decoded fields
// into the result actually runs. The wantStatus, wantIdentity and wantScopes
// assertions are what keep the leak checks honest, since a body the verifier
// cannot parse would silently degrade to a status-only branch that never
// touches the response at all.
func TestVerifiersDoNotLeakResponseBody(t *testing.T) {
	t.Parallel()

	canaries := verifierCanaries()

	engine := NewVerificationEngine(&VerificationConfig{Timeout: time.Second})
	// Sanity floor: 14 built-in verifiers today; a shrunken registration list
	// means verification lost coverage, not that this test should pass.
	if len(engine.verifiers) < 14 {
		t.Fatalf("engine registered %d verifiers, want at least 14", len(engine.verifiers))
	}

	registered := make(map[string]bool, len(engine.verifiers))
	for _, verifier := range engine.verifiers {
		registered[verifier.Name()] = true
		if len(canaries[verifier.Name()]) == 0 {
			t.Errorf("verifier %s has no staged canary exchange; add one so its response handling is exercised instead of skipped", verifier.Name())
		}
	}
	for name := range canaries {
		if !registered[name] {
			t.Errorf("canary exchange %s names no registered verifier; remove it", name)
		}
	}

	for _, verifier := range engine.verifiers {
		var types []SecretType
		for _, st := range probeSecretTypes {
			if verifier.CanVerify(st) {
				types = append(types, st)
			}
		}
		if len(types) == 0 {
			t.Errorf("verifier %s matches no secret type in probeSecretTypes; extend the probe list so it is exercised", verifier.Name())
			continue
		}

		for _, st := range types {
			for _, exchange := range canaries[verifier.Name()] {
				t.Run(verifier.Name()+"/"+string(st)+"/"+exchange.name, func(t *testing.T) {
					t.Parallel()

					result := canaryVerifier(t, verifier.Name(), exchange).Verify(t.Context(), exchange.secret, st)

					raw, err := json.Marshal(result)
					if err != nil {
						t.Fatalf("marshal result: %v", err)
					}
					if strings.Contains(string(raw), bodyCanary) {
						t.Errorf("verifier republished upstream response content into the result: %s", raw)
					}
					if strings.Contains(string(raw), exchange.secret) {
						t.Errorf("verifier echoed the secret value into the result: %s", raw)
					}

					// Without these, an unparseable canary would leave the
					// verifier on a status-only branch and the assertions above
					// would hold for the wrong reason.
					if result.Status != exchange.wantStatus {
						t.Errorf("status = %q, want %q; the canary body did not reach the intended branch (result: %s)", result.Status, exchange.wantStatus, raw)
					}
					if result.Identity != exchange.wantIdentity {
						t.Errorf("identity = %q, want %q", result.Identity, exchange.wantIdentity)
					}
					if !slices.Equal(result.Scopes, exchange.wantScopes) {
						t.Errorf("scopes = %q, want %q", result.Scopes, exchange.wantScopes)
					}
				})
			}
		}
	}
}

// TestUpstreamErrorCode covers the narrowing applied to provider-supplied
// error strings before they reach a VerificationResult.
func TestUpstreamErrorCode(t *testing.T) {
	t.Parallel()

	const secret = "xoxb-canary-slack-token"

	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "documented code passes through", raw: "invalid_auth", want: "invalid_auth"},
		{name: "digits and underscores allowed", raw: "ratelimited_429", want: "ratelimited_429"},
		{name: "empty reports unspecified", raw: "", want: "upstream reported an unspecified error"},
		{name: "free-form prose rejected", raw: "the token you sent has expired", want: "upstream reported an unrecognized error code"},
		{name: "uppercase rejected", raw: "INVALID_AUTH", want: "upstream reported an unrecognized error code"},
		{name: "punctuation rejected", raw: "invalid-auth", want: "upstream reported an unrecognized error code"},
		{name: "overlong value rejected", raw: strings.Repeat("a", 41), want: "upstream reported an unrecognized error code"},
		{name: "reflected secret rejected", raw: secret, want: "upstream reported an unrecognized error code"},
		{name: "embedded secret rejected", raw: "auth_" + secret, want: "upstream reported an unrecognized error code"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := upstreamErrorCode(tt.raw, secret); got != tt.want {
				t.Errorf("upstreamErrorCode(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}
