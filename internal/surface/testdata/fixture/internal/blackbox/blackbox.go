package blackbox

// ForOwnBlackBoxTest is referenced only from this package's external test
// package, so unexporting it means moving that test in-package first.
func ForOwnBlackBoxTest() string { return "bb" }
