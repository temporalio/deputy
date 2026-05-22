package container

import (
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strings"

	"github.com/picatz/deputy/internal/pin"
)

// rewriteContainerRefs rewrites container image references in a file to
// include sha256 digest pins.
func rewriteContainerRefs(root *os.Root, relPath string, updates []pin.Update) error {
	if len(updates) == 0 {
		return nil
	}

	rootFS := root.FS()
	info, err := fs.Stat(rootFS, relPath)
	if err != nil {
		return fmt.Errorf("stat %s: %w", relPath, err)
	}

	content, err := fs.ReadFile(rootFS, relPath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", relPath, err)
	}

	contentStr := string(content)
	modified := false

	for _, u := range updates {
		if err := validateContainerUpdate(u); err != nil {
			return err
		}

		// Match NAME:TAG with optional existing @sha256:digest.
		pattern := fmt.Sprintf(
			`%s:%s(@sha256:[a-fA-F0-9]+)?`,
			regexp.QuoteMeta(u.Name), regexp.QuoteMeta(u.VersionTag),
		)
		re, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("compiling regex for %s: %w", u.Name, err)
		}

		replacement := fmt.Sprintf("%s:%s@%s", u.Name, u.VersionTag, u.PinnedValue)
		newContent := re.ReplaceAllString(contentStr, replacement)
		if newContent != contentStr {
			contentStr = newContent
			modified = true
		}
	}

	if !modified {
		return nil
	}

	f, err := root.OpenFile(relPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, info.Mode().Perm())
	if err != nil {
		return fmt.Errorf("writing %s: %w", relPath, err)
	}

	_, writeErr := f.Write([]byte(contentStr))
	if closeErr := f.Close(); writeErr == nil {
		writeErr = closeErr
	}
	return writeErr
}

// validateContainerUpdate checks that a container Update has valid fields
// to prevent injection via crafted image names or version tags.
func validateContainerUpdate(u pin.Update) error {
	if u.Name == "" {
		return fmt.Errorf("empty image name in update")
	}
	if u.PinnedValue == "" {
		return fmt.Errorf("empty pinned value for %s", u.Name)
	}
	if u.VersionTag == "" {
		return fmt.Errorf("empty version tag for %s", u.Name)
	}
	if !digestRe.MatchString(u.PinnedValue) {
		return fmt.Errorf("pinned value %q for %s is not a valid digest", u.PinnedValue, u.Name)
	}
	// Prevent newline injection in the replacement string.
	if strings.ContainsAny(u.Name, "\n\r") {
		return fmt.Errorf("image name %q for %s contains newlines", u.Name, u.Name)
	}
	if strings.ContainsAny(u.VersionTag, "\n\r") {
		return fmt.Errorf("version tag %q for %s contains newlines", u.VersionTag, u.Name)
	}
	return nil
}
