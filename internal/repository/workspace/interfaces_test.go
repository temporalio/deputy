package workspace

import (
	"io/fs"
	"testing"
)

func TestReadableFS_Interface(t *testing.T) {
	// Verify that our workspace types implement ReadableFS
	var _ ReadableFS = (*LocalDirectory)(nil)
	var _ ReadableFS = (*Memory)(nil)
}

func TestWritableFS_Interface(t *testing.T) {
	// Verify that our workspace types implement WritableFS
	var _ WritableFS = (*LocalDirectory)(nil)
	var _ WritableFS = (*Memory)(nil)
}

func TestMutableFS_Interface(t *testing.T) {
	// Verify that our workspace types implement MutableFS
	var _ MutableFS = (*LocalDirectory)(nil)
	var _ MutableFS = (*Memory)(nil)
}

func TestMetadata_Interface(t *testing.T) {
	// Verify that our workspace types implement Metadata
	var _ Metadata = (*LocalDirectory)(nil)
	var _ Metadata = (*Memory)(nil)
}

func TestFS_Interface(t *testing.T) {
	// Verify that our workspace types implement the unified FS interface
	var _ FS = (*LocalDirectory)(nil)
	var _ FS = (*Memory)(nil)
}

func TestScanner_Interface(t *testing.T) {
	// Verify that our workspace types implement Scanner
	var _ Scanner = (*LocalDirectory)(nil)
	var _ Scanner = (*Memory)(nil)
}

func TestScannerFS_Interface(t *testing.T) {
	// Verify that our workspace types implement ScannerFS
	var _ ScannerFS = (*LocalDirectory)(nil)
	var _ ScannerFS = (*Memory)(nil)
}

func TestToScanner_WithScannerWorkspace(t *testing.T) {
	tmpDir := t.TempDir()
	ws, err := NewDir(tmpDir)
	if err != nil {
		t.Fatalf("failed to create workspace: %v", err)
	}
	defer ws.Close()

	scanner := ToScanner(ws)
	roots := scanner.ScanRoots()

	if len(roots) == 0 {
		t.Error("expected at least one scan root")
	}
	if roots[0] == nil {
		t.Error("expected non-nil scan root")
	}
}

func TestToScanner_WithVirtualWorkspace(t *testing.T) {
	ws := NewMemory()
	defer ws.Close()

	scanner := ToScanner(ws)
	roots := scanner.ScanRoots()

	if len(roots) == 0 {
		t.Error("expected at least one scan root")
	}
	if roots[0] == nil {
		t.Error("expected non-nil scan root")
	}
}

func TestToScanner_CachesExistingScanner(t *testing.T) {
	tmpDir := t.TempDir()
	ws, err := NewDir(tmpDir)
	if err != nil {
		t.Fatalf("failed to create workspace: %v", err)
	}
	defer ws.Close()

	// ToScanner should return the workspace's own Scanner implementation
	scanner1 := ToScanner(ws)
	scanner2 := ToScanner(ws)

	roots1 := scanner1.ScanRoots()
	roots2 := scanner2.ScanRoots()

	// Both should return the same scan roots
	if len(roots1) != len(roots2) {
		t.Errorf("expected same number of roots, got %d and %d", len(roots1), len(roots2))
	}
}

func TestInterfaceComposition(t *testing.T) {
	// Verify that FS properly composes other interfaces
	var testFS FS

	// Should be assignable to ReadableFS
	var _ ReadableFS = testFS

	// Should be assignable to WritableFS
	var _ WritableFS = testFS

	// Should be assignable to Metadata
	var _ Metadata = testFS

	// Should be assignable to fs.FS from standard library
	var _ fs.FS = testFS

	// Should be assignable to fs.ReadDirFS
	var _ fs.ReadDirFS = testFS

	// Should be assignable to fs.StatFS
	var _ fs.StatFS = testFS
}

func TestScannerAdapterImplementation(t *testing.T) {
	// Verify scannerAdapter implements Scanner
	var _ Scanner = (*scannerAdapter)(nil)
}

func TestBackwardCompatibility(t *testing.T) {
	// Verify deprecated interfaces still work
	var testFS FS

	// FileReader should still be assignable
	var _ FileReader = testFS

	// Mutable should still work (it's now just an alias for FS)
	var _ Mutable = testFS
}
