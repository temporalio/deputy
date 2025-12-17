package analysis

import "github.com/picatz/deputy/internal/collections"

// ManagerRank returns a ranking integer for package managers to enforce a
// consistent display order across commands. Lower values indicate higher
// priority (displayed first). Returns 100 for unrecognized managers.
//
// The ordering generally follows:
//   - Go ecosystem (0)
//   - JavaScript ecosystem: npm (1), pnpm (2), yarn (3)
//   - PHP: composer (4)
//   - Ruby: gem (5)
//   - Rust: cargo (6)
//   - Python ecosystem: pip (7), pipenv (8), poetry (9)
//   - Java ecosystem: maven (10), gradle (11)
func ManagerRank(name string) int {
	switch collections.NormalizeLower(name) {
	case "go":
		return 0
	case "npm":
		return 1
	case "pnpm":
		return 2
	case "yarn":
		return 3
	case "composer":
		return 4
	case "gem":
		return 5
	case "cargo":
		return 6
	case "pip":
		return 7
	case "pipenv":
		return 8
	case "poetry":
		return 9
	case "maven":
		return 10
	case "gradle":
		return 11
	default:
		return 100
	}
}
