package jwt

import "context"

// DefaultTenantClaimKey is the default claim key used for tenant identification.
const DefaultTenantClaimKey = "tenant"

// TenantFromContext extracts the tenant identifier from JWT claims in the context.
// Returns empty string if no tenant claim is present or if the request is anonymous.
// Uses the default claim key "tenant".
func TenantFromContext(ctx context.Context) string {
	return TenantFromContextWithKey(ctx, DefaultTenantClaimKey)
}

// TenantFromContextWithKey extracts a tenant using a custom claim key.
// Returns empty string if:
//   - ctx is nil
//   - no claims are present in context (anonymous request)
//   - the specified claim key doesn't exist
//   - the claim value cannot be converted to a string
func TenantFromContextWithKey(ctx context.Context, claimKey string) string {
	claims := ClaimsFromContext(ctx)
	if claims == nil {
		return ""
	}

	value := claims.Get(claimKey)
	if value == nil {
		return ""
	}

	// Handle different types that might be used for tenant claim
	switch v := value.(type) {
	case string:
		return v
	case []byte:
		return string(v)
	default:
		// For other types (int, float, etc.), return empty string
		// as tenant identifiers should be strings
		return ""
	}
}
