package orphan

import "testing"

func TestOrphaned(t *testing.T) {
	if Orphaned() != 1 {
		t.Fatal("bad")
	}
}
