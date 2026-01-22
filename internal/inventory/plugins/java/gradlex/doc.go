// Package gradlex provides Gradle dependency extractors for Deputy.
//
// This package implements multiple strategies for extracting Java/Maven dependencies
// from Gradle projects:
//
//   - verification-metadata.xml: Parses Gradle's dependency verification metadata
//   - gradle.lockfile: Parses Gradle dependency lockfiles (handled by OSV-SCALIBR)
//   - build.gradle: Static parsing of Gradle build scripts to extract declared dependencies
//   - gradle.properties: Parses property files for version variable resolution
//   - libs.versions.toml: Parses Gradle version catalogs
//
// The extractors work together with the GradleResolver in internal/dependency/graph
// to build complete dependency graphs using deps.dev for transitive resolution.
//
// # Extraction Strategy
//
// For Gradle projects without lockfiles, the extraction follows this process:
//
//  1. Parse gradle.properties and build.gradle ext{} blocks for version variables
//  2. Parse libs.versions.toml for version catalog definitions
//  3. Parse build.gradle files to extract dependency declarations
//  4. Substitute version variables to get concrete coordinates
//  5. Use deps.dev GetDependencies API to resolve transitive dependencies
//
// This approach handles most Gradle projects without requiring Gradle execution,
// though complex projects with programmatic dependency generation may need the
// sandbox-based Gradle execution fallback.
package gradlex
