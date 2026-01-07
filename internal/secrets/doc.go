// Package secrets provides secret detection capabilities for Deputy.
//
// This package integrates Google's Veles secret scanner from OSV-SCALIBR
// to detect leaked credentials in source code, container images, and
// other artifacts. It serves two primary purposes:
//
//  1. Security scanning: Detect secrets in scanned targets (containers,
//     repositories, SBOMs) as part of vulnerability analysis.
//
//  2. Agent masking: Mask detected secrets in AI agent sessions to prevent
//     accidental exposure of credentials in prompts and responses.
//
// # Supported Secret Types
//
// Currently supported detectors (via Veles):
//   - GCP API Keys
//   - GCP Service Account Keys (JSON)
//   - RubyGems API Keys
//
// Additional pattern-based detection:
//   - AWS access keys and secret keys
//   - GitHub tokens (classic and fine-grained)
//   - Generic high-entropy strings
//   - Environment variable patterns (PASSWORD, SECRET, TOKEN, etc.)
//
// # Usage
//
// Basic secret detection:
//
//	engine, err := secrets.NewEngine()
//	if err != nil {
//	    return err
//	}
//
//	findings, err := engine.ScanFile(ctx, "config.json", content)
//	for _, f := range findings {
//	    fmt.Printf("Found %s at line %d\n", f.Type, f.Line)
//	}
//
// Masking secrets for AI agents:
//
//	masker := secrets.NewMasker(engine)
//	safe := masker.Mask(userInput)
//	// safe now has secrets replaced with [REDACTED:SECRET_TYPE]
//
// # Policy Integration
//
// Secret findings can be exposed to CEL policies via the `secrets` variable:
//
//	policies:
//	  - name: no-secrets-in-images
//	    entrypoints: ["scan_report"]
//	    rules:
//	      - action: deny
//	        when: secrets.exists(s, s.type == "gcp_service_account_key")
//	        reason: "GCP service account key found in image"
//
// # References
//
//   - Veles: https://github.com/google/osv-scalibr/tree/main/veles
//   - Deputy security patterns: internal/security/env.go
package secrets
