// Package actionsx extracts GitHub Actions dependencies from workflow and action
// manifests.
//
// It inventories:
//   - Step-level uses statements in .github/workflows/*.yml|yaml
//   - Job-level reusable workflow uses statements
//   - Local composite actions referenced via uses: ./path (recursively)
//   - Local reusable workflows referenced via jobs.<id>.uses: ./...yml
//   - Self-repository references (uses: $/path), resolved repo-root-relative
//   - Docker actions referenced via docker://... and runs.image docker://...
//
// The extractor is offline and performs no network fetches; remote actions are
// represented as packages with PURL type "github" so downstream enrichment can
// query OSV and licenses.
package actionsx
