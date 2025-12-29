package flags

import (
	"fmt"
	"strings"
)

// UnsupportedFormatError returns a consistent error for unsupported format flags.
// If flagName is empty, the message omits the flag prefix.
func UnsupportedFormatError(flagName, format, hint string) error {
	name := strings.TrimSpace(flagName)
	if name == "" {
		return fmt.Errorf("unsupported format %q (use %s)", format, hint)
	}
	return fmt.Errorf("unsupported %s %q (use %s)", name, format, hint)
}
