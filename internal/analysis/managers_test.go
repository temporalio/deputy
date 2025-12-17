package analysis

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
		{"maven", 10},
		{"gradle", 11},
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
	// Verify that Go < npm < pnpm < yarn < ... < gradle < unknown
	managers := []string{"go", "npm", "pnpm", "yarn", "composer", "gem", "cargo", "pip", "pipenv", "poetry", "maven", "gradle"}

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
