// Example Deputy extractor plugin that discovers .env files and reports them.
//
// This demonstrates how to build a custom extractor plugin using the Deputy
// plugin SDK. The plugin extracts "packages" representing environment variable
// files, which could be useful for secret scanning or configuration auditing.
//
// # Building
//
//	go build -o deputy-extractor-dotenv ./examples/plugins/dotenv-extractor
//
// # Usage with Deputy
//
// Register the plugin in your .deputy.yaml:
//
//	plugins:
//	  extractors:
//	    - path: ./deputy-extractor-dotenv
//
// Or place it in PATH with the name "deputy-extractor-dotenv".
//
// # Testing the Plugin
//
// You can test the plugin directly:
//
//	# Get plugin info
//	./deputy-extractor-dotenv --spec
//
//	# Check if a file is required (via JSON)
//	echo '{"path":".env"}' | ./deputy-extractor-dotenv file-required --format json
//
//	# Extract packages
//	echo '{"path":".env","contents":"SEKF9V...","root":"/project"}' | ./deputy-extractor-dotenv extract --format json
package main

import (
	"bufio"
	"bytes"
	"path/filepath"
	"strings"

	"github.com/temporalio/deputy/sdk/plugin"
)

func main() {
	plugin.Main(&dotenvExtractor{})
}

// dotenvExtractor extracts .env file metadata as packages.
type dotenvExtractor struct{}

func (e *dotenvExtractor) Name() string {
	return "config/dotenv"
}

func (e *dotenvExtractor) DisplayName() string {
	return "Dotenv Configuration"
}

func (e *dotenvExtractor) Ecosystem() string {
	return "config"
}

func (e *dotenvExtractor) Version() int {
	return 1
}

func (e *dotenvExtractor) Description() string {
	return "Extracts environment variable files (.env, .env.*) for configuration auditing"
}

func (e *dotenvExtractor) FilePatterns() []string {
	return []string{".env", ".env.*", "*.env"}
}

func (e *dotenvExtractor) FileRequired(path string, isDir bool, mode uint32, size int64) bool {
	if isDir {
		return false
	}

	base := filepath.Base(path)

	// Match .env, .env.local, .env.production, etc.
	if base == ".env" || strings.HasPrefix(base, ".env.") {
		return true
	}

	// Match *.env files like production.env
	if strings.HasSuffix(base, ".env") {
		return true
	}

	return false
}

func (e *dotenvExtractor) Extract(path string, contents []byte, root string) ([]*plugin.Package, error) {
	// Parse the .env file to count variables and detect potential issues
	var varCount int
	var sensitiveVars []string

	scanner := bufio.NewScanner(bytes.NewReader(contents))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Count variables
		if strings.Contains(line, "=") {
			varCount++

			// Check for potentially sensitive variable names
			varName, _, _ := strings.Cut(line, "=")
			varName = strings.ToUpper(varName)
			if isSensitiveVarName(varName) {
				sensitiveVars = append(sensitiveVars, varName)
			}
		}
	}

	// Create a "package" representing this env file
	// In a real extractor, you might parse actual dependencies
	pkg := plugin.NewPackageBuilder(filepath.Base(path), "1.0.0", "config").
		WithLocations(path).
		WithDirect(true).
		Build()

	return []*plugin.Package{pkg}, nil
}

// isSensitiveVarName checks if a variable name suggests sensitive data.
func isSensitiveVarName(name string) bool {
	sensitivePatterns := []string{
		"SECRET", "PASSWORD", "PASSWD", "PWD",
		"KEY", "TOKEN", "API_KEY", "APIKEY",
		"CREDENTIAL", "AUTH", "PRIVATE",
		"AWS_ACCESS", "AWS_SECRET",
		"DATABASE_URL", "DB_PASSWORD",
	}

	for _, pattern := range sensitivePatterns {
		if strings.Contains(name, pattern) {
			return true
		}
	}
	return false
}
