package used

import (
	"testing"

	"fixture/internal/testonly"
)

func TestLocal(t *testing.T) {
	if Local() == "" || selfReference() == "" {
		t.Fatal("empty")
	}
	if testonly.ForForeignTests() == "" {
		t.Fatal("empty")
	}
}
