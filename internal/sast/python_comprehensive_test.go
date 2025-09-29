package sast

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPythonComprehensiveSecurity(t *testing.T) {
	// Create a comprehensive test with multiple vulnerability types
	dir := t.TempDir()
	pythonContent := `
import os
import subprocess
import sqlite3
import pickle
import yaml
from flask import Flask, request, render_template
from django.http import HttpResponse
import html
import urllib.parse

app = Flask(__name__)

# Multiple vulnerability types in one file
def comprehensive_vulnerabilities():
    # Taint sources
    user_input = input("Enter data: ")
    env_var = os.environ.get('USER_CONFIG')
    web_param = request.args.get('param')
    
    # Command injection
    os.system(f"ls {user_input}")
    subprocess.call(f"echo {env_var}", shell=True)
    
    # Code injection
    eval(web_param)
    exec(user_input)
    
    # SQL injection
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{user_input}'")
    
    # XSS
    response = HttpResponse(f"<h1>Hello {user_input}</h1>")
    template = render_template('page.html', message=web_param)
    
    # Path traversal
    with open(f"/uploads/{user_input}", 'r') as f:
        content = f.read()
    
    # Unsafe deserialization
    obj = pickle.loads(user_input)
    config = yaml.load(env_var)
    
    # Sanitizers
    safe_html = html.escape(user_input)
    safe_url = urllib.parse.quote(web_param)
    
    return response, template, content, obj, config, safe_html, safe_url

# Class-based vulnerabilities
class SecurityTest:
    def __init__(self):
        self.db = sqlite3.connect('test.db')
    
    def vulnerable_method(self, data):
        # Method-level vulnerabilities
        os.system(f"process {data}")
        cursor = self.db.cursor()
        cursor.execute(f"INSERT INTO logs VALUES ('{data}')")
    
    def safe_method(self, data):
        # Safe operations
        safe_data = html.escape(data)
        return safe_data

if __name__ == "__main__":
    comprehensive_vulnerabilities()
    test = SecurityTest()
    test.vulnerable_method("test")
`
	if err := os.WriteFile(filepath.Join(dir, "comprehensive.py"), []byte(pythonContent), 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	target := &Target{FS: os.DirFS(dir)}
	dialect := NewPythonDialect()

	// Test the full pipeline
	if !dialect.Supports(target) {
		t.Fatal("Python dialect should support Python files")
	}

	units, err := dialect.DiscoverUnits(context.Background(), target)
	if err != nil {
		t.Fatalf("Failed to discover units: %v", err)
	}

	if len(units) == 0 {
		t.Fatal("Expected at least one compilation unit")
	}

	err = dialect.Prepare(context.Background(), units[0])
	if err != nil {
		t.Fatalf("Failed to prepare unit: %v", err)
	}

	irPkg, err := dialect.LowerToIR(context.Background(), units[0])
	if err != nil {
		t.Fatalf("Failed to lower to IR: %v", err)
	}

	// Verify we have symbols and a graph
	if len(irPkg.Symbols) == 0 {
		t.Error("Expected symbols to be generated")
	}

	if irPkg.Graph == nil {
		t.Fatal("Expected graph to be generated")
	}

	// Count all vulnerability types
	cmdInjCount := countPythonVulnerabilities(irPkg, "command_injection")
	codeInjCount := countPythonVulnerabilities(irPkg, "code_injection")
	sqlInjCount := countPythonVulnerabilities(irPkg, "sql_injection")
	xssCount := countPythonVulnerabilities(irPkg, "xss")
	pathCount := countPythonVulnerabilities(irPkg, "path_traversal")
	deserCount := countPythonVulnerabilities(irPkg, "unsafe_deserialization")
	taintCount := countPythonVulnerabilities(irPkg, "taint_source")
	sanitizerCount := countPythonVulnerabilities(irPkg, "sanitizer")

	t.Logf("Comprehensive Python security analysis results:")
	t.Logf("  Symbols generated: %d", len(irPkg.Symbols))
	t.Logf("  Entry points: %d", len(irPkg.Entrypoints))
	t.Logf("  Command injection: %d", cmdInjCount)
	t.Logf("  Code injection: %d", codeInjCount)
	t.Logf("  SQL injection: %d", sqlInjCount)
	t.Logf("  XSS: %d", xssCount)
	t.Logf("  Path traversal: %d", pathCount)
	t.Logf("  Unsafe deserialization: %d", deserCount)
	t.Logf("  Taint sources: %d", taintCount)
	t.Logf("  Sanitizers: %d", sanitizerCount)

	// Verify we detected multiple vulnerability types
	totalVulns := cmdInjCount + codeInjCount + sqlInjCount + xssCount + pathCount + deserCount
	if totalVulns < 10 {
		t.Errorf("Expected at least 10 vulnerabilities, found %d", totalVulns)
	}

	// Check for specific vulnerabilities we know should be there
	expectedVulns := map[string]int{
		"command_injection":      2, // os.system, subprocess.call
		"code_injection":         2, // eval, exec
		"sql_injection":          2, // cursor.execute calls
		"xss":                    2, // HttpResponse, render_template
		"path_traversal":         1, // open with user input
		"unsafe_deserialization": 2, // pickle.loads, yaml.load
		"taint_source":           3, // input, os.environ, request.args
		"sanitizer":              2, // html.escape, urllib.parse.quote
	}

	for vulnType, expectedCount := range expectedVulns {
		actualCount := countPythonVulnerabilities(irPkg, vulnType)
		if actualCount < expectedCount {
			t.Errorf("Expected at least %d %s vulnerabilities, found %d",
				expectedCount, vulnType, actualCount)
		}
	}

	// Verify entry points are detected
	if len(irPkg.Entrypoints) == 0 {
		t.Error("Expected entry points to be detected")
	}

	// Check that we have call edges
	snapshot := irPkg.Graph.Snapshot()
	hasCallEdges := false
	for _, symbol := range snapshot.Symbols() {
		if len(snapshot.OutgoingEdges(EdgeKindCall, symbol.ID)) > 0 {
			hasCallEdges = true
			break
		}
	}

	if !hasCallEdges {
		t.Error("Expected call edges to be generated")
	}
}
