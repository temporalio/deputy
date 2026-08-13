package awkward

import "testing"

func TestAwkward(t *testing.T) {
	if Awkward() != 1 {
		t.Fatal("bad")
	}
}
