package ecosystem

import "testing"

func TestManagerRank(t *testing.T) {
	tests := []struct {
		name string
		want int
	}{
		{"go", 0},
		{"Go", 0},
		{"  go  ", 0},
		{"npm", 1},
		{"pnpm", 2},
		{"yarn", 3},
		{"composer", 4},
		{"gem", 5},
		{"cargo", 6},
		{"pip", 7},
		{"pipenv", 8},
		{"poetry", 9},
		{"uv", 10},
		{"pdm", 11},
		{"conda", 12},
		{"maven", 13},
		{"gradle", 14},
		{"nuget", 15},
		{"dotnet", 15},
		{"hex", 16},
		{"mix", 16},
		{"pub", 17},
		{"cocoapods", 18},
		{"mise", 24},
		{"asdf", 25},
		{"github-actions", 26},
		{"githubactions", 26},
		{"docker", 27},
		{"oci", 27},
		{"unknown", 100},
		{"", 100},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ManagerRank(tt.name); got != tt.want {
				t.Errorf("ManagerRank(%q) = %d, want %d", tt.name, got, tt.want)
			}
		})
	}
}

func TestManagerRank_Ordering(t *testing.T) {
	// Verify that Go < npm < pnpm < ... < docker < unknown
	managers := []string{
		"go", "npm", "pnpm", "yarn", "composer", "gem", "cargo",
		"pip", "pipenv", "poetry", "uv", "pdm", "conda",
		"maven", "gradle", "nuget", "hex", "pub", "cocoapods",
		"cabal", "stack", "renv", "conan", "mise", "asdf",
		"github-actions", "docker",
	}

	for i := 1; i < len(managers); i++ {
		prev := managers[i-1]
		curr := managers[i]
		if ManagerRank(prev) >= ManagerRank(curr) {
			t.Errorf("ManagerRank(%q)=%d should be less than ManagerRank(%q)=%d",
				prev, ManagerRank(prev), curr, ManagerRank(curr))
		}
	}

	// Unknown should be last
	last := managers[len(managers)-1]
	if ManagerRank(last) >= ManagerRank("unknown") {
		t.Errorf("ManagerRank(%q)=%d should be less than ManagerRank(unknown)=%d",
			last, ManagerRank(last), ManagerRank("unknown"))
	}
}

// TestManagerRank_ToolchainManagersRecognized guards against mise/asdf falling
// back to the unrecognized-manager rank: they are first-class ecosystems and
// their toolchain fixes must not sort behind every other manager.
func TestManagerRank_ToolchainManagersRecognized(t *testing.T) {
	defaultRank := ManagerRank("unknown")
	for _, manager := range []string{"mise", "asdf"} {
		t.Run(manager, func(t *testing.T) {
			if got := ManagerRank(manager); got >= defaultRank {
				t.Errorf("ManagerRank(%q) = %d, want a recognized rank below the default %d", manager, got, defaultRank)
			}
		})
	}
}
