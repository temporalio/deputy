package blackbox_test

import (
	"testing"

	"fixture/internal/blackbox"
)

func TestForOwnBlackBoxTest(t *testing.T) {
	if blackbox.ForOwnBlackBoxTest() == "" {
		t.Fatal("empty")
	}
}
