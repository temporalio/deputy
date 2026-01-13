// Package dockerfile provides Dockerfile parsing and static analysis for policy evaluation.
//
// This package parses Dockerfiles into a structured representation suitable for
// CEL policy evaluation, enabling security checks without building images.
//
// # Parsing
//
// Parse Dockerfiles from files, byte slices, or readers:
//
//	info, err := dockerfile.ParseFile("Dockerfile")
//	info, err := dockerfile.ParseBytes(content)
//	info, err := dockerfile.Parse(reader)
//
// # Data Model
//
// [Info] is the top-level container with:
//   - Stages: All build stages from FROM instructions
//   - Args: ARG instructions with default values
//   - FinalStage: The stage that produces the final image
//
// [Stage] captures per-stage information:
//   - Base image reference (raw and resolved after ARG substitution)
//   - USER, WORKDIR, ENV, EXPOSE, LABEL directives
//   - RUN, COPY, ADD instructions for security analysis
//   - HEALTHCHECK configuration
//   - ENTRYPOINT and CMD
//
// # Policy Variables
//
// When used with Deputy's policy engine, the parsed Dockerfile is exposed as:
//
//	dockerfile.path           - File path
//	dockerfile.stages         - All build stages
//	dockerfile.args           - ARG defaults
//	dockerfile.final_stage    - Last stage
//
// And for dockerfile_stage entrypoint:
//
//	stage.index               - Stage position (0-based)
//	stage.name                - AS alias
//	stage.base_image          - FROM image as written
//	stage.base_image_resolved - Parsed image reference
//	stage.user                - USER directive
//	stage.is_root             - True if running as root
//	stage.is_scratch          - True if FROM scratch
//	stage.healthcheck         - HEALTHCHECK config (or nil)
//
// # Analysis
//
// [Analyze] performs static analysis on parsed Dockerfiles:
//
//	analysis := dockerfile.Analyze(info)
//
// [Analysis] provides computed properties:
//   - StageCount, HasMultiStage, BuilderStageCount
//   - FinalStageIsRoot, FinalStageIsScratch
//   - SensitiveEnvVars (detected secrets in ENV)
//   - HasAddURL (ADD with remote URLs - security risk)
//
// # Security Checks
//
// Common security patterns detected:
//   - Running as root (User == "" or "0" or "root")
//   - Secrets in environment variables (AWS_SECRET, API_KEY, etc.)
//   - ADD with URLs (supply chain risk)
//   - Missing HEALTHCHECK in production stages
//   - Unpinned base images (:latest or no tag)
//
// # Example Policy
//
//	# Block images running as root
//	rules:
//	  - action: deny
//	    when: dockerfile.final_stage.is_root && !dockerfile.final_stage.is_scratch
//	    reason: "Final stage runs as root"
//
// # Related Packages
//
//   - [internal/policy] - CEL policy evaluation
//   - [internal/container/image] - Runtime image analysis
//   - [internal/server] - Dockerfile scanning via ScanHandler
package dockerfile
