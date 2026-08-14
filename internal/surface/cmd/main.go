// Command surface audits Deputy's internal API surface and prints what no
// other package reaches: unimported packages, exported symbols nothing outside
// their package references, and exported interfaces nothing accepts as a
// parameter or holds as a field.
//
// Run it from anywhere in the repository:
//
//	go run ./internal/surface/cmd              # summary
//	go run ./internal/surface/cmd -json        # dump for ad-hoc filtering
//	go run ./internal/surface/cmd -pkg auth    # per-symbol detail for a package
//	go run ./internal/surface/cmd -baseline    # rewrite the unreachable-package baseline
//
// Findings the audit has reason to doubt (reflection, encoding, interface
// dispatch, lookup by name) are reported with those reasons rather than
// asserted, because a symbol reached dynamically looks identical to a dead one.
//
// The -json output is a dump of the in-process [surface.Report], keyed by Go
// field name. It exists to be piped through jq while reading a run, and it is
// not a format to write a program against: nothing versions it and it changes
// with the struct. The one output that is pinned is the text baseline at
// [surface.BaselinePath], which a test compares against. If something ever needs
// to consume the audit rather than read it, that consumer makes this a contract,
// and a contract belongs in proto with the rest of Deputy's cross-surface
// output.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"

	"github.com/temporalio/deputy/internal/surface"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "surface:", err)
		os.Exit(1)
	}
}

// run parses flags, audits the module, and renders the requested view. Keeping
// it separate from main means every exit path returns an error instead of
// calling os.Exit from inside the logic.
func run() error {
	var (
		asJSON   = flag.Bool("json", false, "dump the report as JSON for ad-hoc filtering; keyed by Go field name and not a stable format")
		pkg      = flag.String("pkg", "", "print per-symbol detail for packages whose path ends with this suffix")
		baseline = flag.Bool("baseline", false, "rewrite the unreachable-package baseline the drift test pins")
	)
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	root, err := repoRoot()
	if err != nil {
		return err
	}
	report, err := surface.Analyze(ctx, root)
	if err != nil {
		return err
	}

	switch {
	case *baseline:
		path := filepath.Join(root, filepath.FromSlash(surface.BaselinePath))
		if err := surface.WriteBaseline(path, report); err != nil {
			return err
		}
		fmt.Printf("wrote %s (%d packages)\n", surface.BaselinePath, len(report.Packages))
		return nil
	case *asJSON:
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	case *pkg != "":
		return report.Detail(os.Stdout, *pkg)
	default:
		return report.Text(os.Stdout)
	}
}

// repoRoot walks up from the working directory to the module root, so the
// command works from the repository root and from any package directory.
func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("no go.mod found above %s", dir)
		}
		dir = parent
	}
}
