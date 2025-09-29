package sast

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestPythonSASTExample demonstrates the complete Python SAST workflow
func TestPythonSASTExample(t *testing.T) {
	// Create a realistic Python web application with vulnerabilities
	dir := t.TempDir()
	
	// Main application file
	appContent := `
from flask import Flask, request, render_template
import os
import sqlite3
import pickle

app = Flask(__name__)

@app.route('/user/<user_id>')
def get_user(user_id):
    # SQL injection vulnerability
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    user = cursor.fetchone()
    
    # XSS vulnerability
    return f"<h1>User: {user[1]}</h1>"

@app.route('/search')
def search():
    query = request.args.get('q')
    
    # Command injection vulnerability
    os.system(f"grep '{query}' logs.txt")
    
    # Code injection vulnerability
    eval(f"result = process_query('{query}')")
    
    return render_template('results.html', query=query)

@app.route('/upload', methods=['POST'])
def upload_file():
    filename = request.form.get('filename')
    
    # Path traversal vulnerability
    with open(f"/uploads/{filename}", 'w') as f:
        f.write(request.form.get('content'))
    
    return "File uploaded"

@app.route('/load_config', methods=['POST'])
def load_config():
    config_data = request.form.get('config')
    
    # Unsafe deserialization vulnerability
    config = pickle.loads(config_data.encode())
    
    return f"Config loaded: {config}"

if __name__ == '__main__':
    app.run(debug=True)
`
	
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(appContent), 0o644); err != nil {
		t.Fatalf("Failed to write app.py: %v", err)
	}
	
	// Helper module
	helperContent := `
import html
import urllib.parse

def sanitize_input(user_input):
    # Proper sanitization
    return html.escape(user_input)

def safe_url_encode(data):
    # Safe URL encoding
    return urllib.parse.quote(data)

def process_query(query):
    # Safe query processing
    return sanitize_input(query).lower()
`
	
	if err := os.WriteFile(filepath.Join(dir, "helpers.py"), []byte(helperContent), 0o644); err != nil {
		t.Fatalf("Failed to write helpers.py: %v", err)
	}

	// Run Python SAST analysis
	target := &Target{FS: os.DirFS(dir)}
	dialect := NewPythonDialect()

	if !dialect.Supports(target) {
		t.Fatal("Python dialect should support Python files")
	}

	units, err := dialect.DiscoverUnits(context.Background(), target)
	if err != nil {
		t.Fatalf("Failed to discover units: %v", err)
	}

	if len(units) == 0 {
		t.Fatal("Expected compilation units")
	}

	// Process each unit
	var totalVulns int
	for _, unit := range units {
		err = dialect.Prepare(context.Background(), unit)
		if err != nil {
			t.Fatalf("Failed to prepare unit %s: %v", unit.Path, err)
		}

		irPkg, err := dialect.LowerToIR(context.Background(), unit)
		if err != nil {
			t.Fatalf("Failed to lower unit %s to IR: %v", unit.Path, err)
		}

		// Count vulnerabilities in this unit
		unitVulns := 0
		vulnTypes := []string{
			"command_injection", "code_injection", "sql_injection",
			"xss", "path_traversal", "unsafe_deserialization",
		}
		
		for _, vulnType := range vulnTypes {
			count := countPythonVulnerabilities(irPkg, vulnType)
			totalVulns += count
			unitVulns += count
			if count > 0 {
				t.Logf("Found %d %s vulnerabilities in %s", count, vulnType, unit.Path)
			}
		}
		
		// Count taint sources and sanitizers
		taintSources := countPythonVulnerabilities(irPkg, "taint_source")
		sanitizers := countPythonVulnerabilities(irPkg, "sanitizer")
		
		t.Logf("Unit %s: %d vulnerabilities, %d taint sources, %d sanitizers", 
			unit.Path, unitVulns, taintSources, sanitizers)
	}

	t.Logf("Python SAST Analysis Complete:")
	t.Logf("  Total compilation units: %d", len(units))
	t.Logf("  Total vulnerabilities found: %d", totalVulns)

	// Verify we found the expected vulnerabilities
	if totalVulns < 5 {
		t.Errorf("Expected at least 5 vulnerabilities in the test application, found %d", totalVulns)
	}

	t.Log("✅ Python SAST successfully detected multiple security vulnerabilities!")
}