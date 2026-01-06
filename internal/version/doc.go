// Package version provides build-time version information for Deputy.
//
// The version is set at build time using ldflags:
//
//	go build -ldflags "-X github.com/picatz/deputy/internal/version.Value=v1.0.0"
//
// # Usage
//
// Access the current version:
//
//	fmt.Printf("Deputy %s\n", version.Value)
//
// The [Value] variable defaults to "dev" when not set via ldflags,
// indicating a development build.
//
// # Build Integration
//
// The version is typically set by GoReleaser or CI scripts:
//
//	# In .goreleaser.yaml
//	ldflags:
//	  - -X github.com/picatz/deputy/internal/version.Value={{.Version}}
//
// # CLI Integration
//
// The version command displays this information:
//
//	$ deputy version
//	deputy v1.0.0
package version
