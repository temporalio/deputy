package githubactions

import (
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strings"

	"github.com/temporalio/deputy/internal/pin"
)

// RewriteWorkflow applies pin updates to a single workflow file within the
// given root directory. It uses regex-based replacement to preserve YAML
// formatting, indentation, quotes, and unrelated comments.
//
// The output format is Dependabot-compatible:
//
//	uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
func RewriteWorkflow(root *os.Root, relPath string, updates []pin.Update) error {
	if len(updates) == 0 {
		return nil
	}

	// Capture original permissions so we can preserve them on write-back.
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
		if err := validateUpdate(u); err != nil {
			return err
		}

		escapedRef := regexp.QuoteMeta(u.Name)

		// Match: uses: <optional-quote><action-ref>@<old-ref><optional-quote><optional-comment>
		// Captures:
		//   1: prefix including "uses:" and optional quote
		//   2: the action ref (owner/repo or owner/repo/subpath)
		//   3: the old version/SHA ref (full token)
		//   4: optional trailing quote
		//   5: everything after the ref on the same line (comment, etc.)
		pattern := fmt.Sprintf(
			`(uses:\s*["']?)(%s)@([^\s"'#]+)(["']?)(\s*#[^\n]*)?`,
			escapedRef,
		)
		re, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("compiling regex for %s: %w", u.Name, err)
		}

		// Rewrite only occurrences whose original ref exactly equals this
		// update's FromVersion, so multiple versions of the same action in one
		// file (e.g. actions/checkout@v4 and @v6) each pin to their own SHA
		// instead of all collapsing to one. An empty FromVersion matches any.
		// The full-token capture (group 3) plus this equality check prevents a
		// short version (e.g. "v4") from partially matching a longer one ("v44").
		newContent := re.ReplaceAllStringFunc(contentStr, func(match string) string {
			m := re.FindStringSubmatch(match)
			if m == nil {
				return match
			}
			if u.FromVersion != "" && m[3] != u.FromVersion {
				return match
			}
			return m[1] + m[2] + "@" + u.PinnedValue + m[4] + " # " + u.VersionTag
		})
		if newContent != contentStr {
			contentStr = newContent
			modified = true
		}
	}

	if !modified {
		return nil
	}

	// Write back via os.Root for path-traversal safety.
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

// validateUpdate checks that an Update has valid fields to prevent injection
// via crafted version tags or pinned values.
func validateUpdate(u pin.Update) error {
	if u.Name == "" {
		return fmt.Errorf("empty action name in update")
	}
	if u.PinnedValue == "" {
		return fmt.Errorf("empty pinned value for %s", u.Name)
	}
	// PinnedValue must be a valid 40-char hex SHA
	if !pin.IsCommitSHA(u.PinnedValue) {
		return fmt.Errorf("pinned value %q for %s is not a valid SHA", u.PinnedValue, u.Name)
	}
	// VersionTag must not contain newlines (injection prevention)
	if strings.ContainsAny(u.VersionTag, "\n\r") {
		return fmt.Errorf("version tag %q for %s contains newlines", u.VersionTag, u.Name)
	}
	return nil
}
