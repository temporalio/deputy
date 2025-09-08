package git

import "testing"

func Test_CalculateSimilarity_basic(t *testing.T) {
	a := "abcdef"
	b := "abcxyz"
	sim := calculateSimilarity(a, b)
	if sim <= 0.4 || sim >= 0.6 { // expect ~0.5
		t.Fatalf("unexpected similarity %v", sim)
	}
}
