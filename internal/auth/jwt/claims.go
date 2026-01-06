package jwt

// Claims represents verified JWT claims exposed to applications.
type Claims struct {
	// Standard claims (RFC 7519)
	Subject   string   `json:"sub,omitempty"`
	Issuer    string   `json:"iss,omitempty"`
	Audience  []string `json:"aud,omitempty"`
	ExpiresAt int64    `json:"exp,omitempty"`
	IssuedAt  int64    `json:"iat,omitempty"`
	NotBefore int64    `json:"nbf,omitempty"`
	JWTID     string   `json:"jti,omitempty"`

	// Custom claims (all other claims from the token)
	Custom map[string]any `json:"-"`
}

// ToMap converts claims to a map suitable for CEL evaluation or JSON serialization.
// The returned map includes an "anonymous" field set to false.
func (c *Claims) ToMap() map[string]any {
	m := map[string]any{
		"anonymous": false,
	}

	// Add standard claims if present
	if c.Subject != "" {
		m["sub"] = c.Subject
	}
	if c.Issuer != "" {
		m["iss"] = c.Issuer
	}
	if len(c.Audience) > 0 {
		m["aud"] = c.Audience
	}
	if c.ExpiresAt != 0 {
		m["exp"] = c.ExpiresAt
	}
	if c.IssuedAt != 0 {
		m["iat"] = c.IssuedAt
	}
	if c.NotBefore != 0 {
		m["nbf"] = c.NotBefore
	}
	if c.JWTID != "" {
		m["jti"] = c.JWTID
	}

	// Merge custom claims at top level for easy access
	for k, v := range c.Custom {
		if _, reserved := m[k]; !reserved {
			m[k] = v
		}
	}

	return m
}

// Get returns a claim value by name, checking both standard and custom claims.
// Returns nil if the claim doesn't exist.
func (c *Claims) Get(name string) any {
	switch name {
	case "sub":
		if c.Subject != "" {
			return c.Subject
		}
	case "iss":
		if c.Issuer != "" {
			return c.Issuer
		}
	case "aud":
		if len(c.Audience) > 0 {
			return c.Audience
		}
	case "exp":
		if c.ExpiresAt != 0 {
			return c.ExpiresAt
		}
	case "iat":
		if c.IssuedAt != 0 {
			return c.IssuedAt
		}
	case "nbf":
		if c.NotBefore != 0 {
			return c.NotBefore
		}
	case "jti":
		if c.JWTID != "" {
			return c.JWTID
		}
	default:
		if v, ok := c.Custom[name]; ok {
			return v
		}
	}
	return nil
}

// Has checks if a claim exists (standard or custom).
func (c *Claims) Has(name string) bool {
	return c.Get(name) != nil
}

// AnonymousClaims returns a claims map indicating anonymous access.
// Use this when no token was provided and anonymous access is allowed.
func AnonymousClaims() map[string]any {
	return map[string]any{
		"anonymous": true,
	}
}
