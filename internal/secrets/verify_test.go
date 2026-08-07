package secrets

import (
	"encoding/json"
	"io"
	"net/http"
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

// TestVerifiersDoNotLeakResponseBody pins the credential-disclosure invariant
// for every registered verifier, not just GitHub: upstream response bodies
// (which can echo the secret or carry other sensitive detail) must never
// surface in a VerificationResult. The corpus is engine.verifiers, so a newly
// registered verifier is covered automatically; each verifier is exercised
// through every secret type it claims via CanVerify against a transport that
// plants a marker in the response body.
func TestVerifiersDoNotLeakResponseBody(t *testing.T) {
	t.Parallel()

	const (
		marker = "RESPONSE-BODY-CANARY-2f8c1d"
		secret = "canary-secret-value"
	)

	engine := NewVerificationEngine(&VerificationConfig{Timeout: time.Second})
	// The verifiers share the engine's HTTP client, so swapping its transport
	// routes every verifier's requests to the marker response.
	engine.client.Transport = roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusInternalServerError,
			Body:       io.NopCloser(strings.NewReader("Token " + secret + " is expired " + marker)),
			Header:     make(http.Header),
		}, nil
	})

	// Sanity floor: 14 built-in verifiers today; a shrunken registration list
	// means verification lost coverage, not that this test should pass.
	if len(engine.verifiers) < 14 {
		t.Fatalf("engine registered %d verifiers, want at least 14", len(engine.verifiers))
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
			t.Run(verifier.Name()+"/"+string(st), func(t *testing.T) {
				t.Parallel()

				result := verifier.Verify(t.Context(), secret, st)

				raw, err := json.Marshal(result)
				if err != nil {
					t.Fatalf("marshal result: %v", err)
				}
				if strings.Contains(string(raw), marker) {
					t.Errorf("verifier leaked the upstream response body into the result: %s", raw)
				}
				if strings.Contains(string(raw), secret) {
					t.Errorf("verifier echoed the secret value into the result: %s", raw)
				}
			})
		}
	}
}
