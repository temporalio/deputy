package secrets

import (
	"context"
	"strings"
	"sync"
)

// Masker provides secret masking capabilities for text content.
// It is designed for use with AI agents to prevent accidental
// exposure of credentials in prompts and responses.
type Masker struct {
	engine *Engine
	mu     sync.RWMutex
	// knownSecrets caches detected secrets for consistent masking
	knownSecrets map[string]SecretType
}

// NewMasker creates a new Masker with the given detection engine.
func NewMasker(engine *Engine) *Masker {
	return &Masker{
		engine:       engine,
		knownSecrets: make(map[string]SecretType),
	}
}

// Mask scans the input text for secrets and replaces them with
// redacted placeholders. Returns the masked text.
func (m *Masker) Mask(input string) string {
	ctx := context.Background()

	// Scan for secrets
	findings, err := m.engine.Scan(ctx, []byte(input))
	if err != nil {
		// On error, return input unchanged to avoid data loss
		return input
	}

	if len(findings) == 0 {
		return input
	}

	// Cache and replace secrets
	result := input
	m.mu.Lock()
	for _, f := range findings {
		if f.Value != "" {
			m.knownSecrets[f.Value] = f.Type
			result = strings.ReplaceAll(result, f.Value, f.Redacted)
		}
	}
	m.mu.Unlock()

	return result
}

// MaskKnown masks any previously detected secrets without re-scanning.
// This is useful for masking output that may contain secrets detected
// in earlier input.
func (m *Masker) MaskKnown(input string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := input
	for secret, secretType := range m.knownSecrets {
		redacted := redactValue(secret, secretType)
		result = strings.ReplaceAll(result, secret, redacted)
	}
	return result
}

// MaskAndLearn scans input for secrets, caches them, and returns masked text.
// Unlike Mask, this also returns the findings for inspection.
func (m *Masker) MaskAndLearn(input string) (string, []Finding) {
	ctx := context.Background()

	findings, err := m.engine.Scan(ctx, []byte(input))
	if err != nil {
		return input, nil
	}

	if len(findings) == 0 {
		return input, nil
	}

	result := input
	m.mu.Lock()
	for _, f := range findings {
		if f.Value != "" {
			m.knownSecrets[f.Value] = f.Type
			result = strings.ReplaceAll(result, f.Value, f.Redacted)
		}
	}
	m.mu.Unlock()

	return result, findings
}

// AddSecret manually registers a secret value for masking.
// This is useful when secrets are known from other sources
// (e.g., environment variables, configuration files).
func (m *Masker) AddSecret(value string, secretType SecretType) {
	m.mu.Lock()
	m.knownSecrets[value] = secretType
	m.mu.Unlock()
}

// Clear removes all cached secrets.
func (m *Masker) Clear() {
	m.mu.Lock()
	m.knownSecrets = make(map[string]SecretType)
	m.mu.Unlock()
}

// Stats returns the count of known secrets by type.
func (m *Masker) Stats() map[SecretType]int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := make(map[SecretType]int)
	for _, t := range m.knownSecrets {
		stats[t]++
	}
	return stats
}
