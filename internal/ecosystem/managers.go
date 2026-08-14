package ecosystem

import "github.com/temporalio/deputy/internal/collections"

// ManagerRank returns a ranking integer for package managers to enforce a
// consistent display order across commands. Lower values indicate higher
// priority (displayed first). Returns 100 for unrecognized managers.
//
// The ordering generally follows:
//   - Go ecosystem (0)
//   - JavaScript ecosystem: npm (1), pnpm (2), yarn (3)
//   - PHP: composer (4)
//   - Ruby: gem/bundler (5)
//   - Rust: cargo (6)
//   - Python ecosystem: pip (7), pipenv (8), poetry (9), uv (10), pdm (11), conda (12)
//   - Java ecosystem: maven (13), gradle (14)
//   - .NET ecosystem: nuget/dotnet (15)
//   - Elixir ecosystem: hex/mix (16)
//   - Dart ecosystem: pub/dart/flutter (17)
//   - iOS/macOS: cocoapods (18), swift/spm (19)
//   - Haskell: cabal (20), stack (21)
//   - R: renv (22)
//   - C++: conan (23)
//   - Toolchain version managers: mise (24), asdf (25)
//   - CI/CD: github-actions (26)
//   - Container: docker, oci (27)
func ManagerRank(name string) int {
	switch collections.NormalizeLower(name) {
	// Go
	case "go":
		return 0

	// JavaScript/TypeScript
	case "npm":
		return 1
	case "pnpm":
		return 2
	case "yarn":
		return 3

	// PHP
	case "composer":
		return 4

	// Ruby
	case "gem", "bundler":
		return 5

	// Rust
	case "cargo":
		return 6

	// Python
	case "pip":
		return 7
	case "pipenv":
		return 8
	case "poetry":
		return 9
	case "uv":
		return 10
	case "pdm":
		return 11
	case "conda":
		return 12

	// Java
	case "maven":
		return 13
	case "gradle":
		return 14

	// .NET
	case "nuget", "dotnet":
		return 15

	// Elixir/Erlang
	case "hex", "mix":
		return 16

	// Dart/Flutter
	case "pub", "dart", "flutter":
		return 17

	// iOS/macOS
	case "cocoapods", "pod":
		return 18
	case "swift", "spm":
		return 19

	// Haskell
	case "cabal":
		return 20
	case "stack":
		return 21

	// R
	case "renv":
		return 22

	// C++
	case "conan":
		return 23

	// Toolchain version managers (mise, asdf) install language runtimes and
	// dev tools; they sort after single-language managers but ahead of CI/CD
	// and container artifacts.
	case "mise":
		return 24
	case "asdf":
		return 25

	// CI/CD
	case "github-actions", "githubactions":
		return 26

	// Container
	case "docker", "oci", "container":
		return 27

	default:
		return 100
	}
}
