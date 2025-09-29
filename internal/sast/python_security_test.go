package sast

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Helper function to count vulnerabilities by type
func countPythonVulnerabilities(pkg *IRPackage, vulnType string) int {
	count := 0
	snapshot := pkg.Graph.Snapshot()
	for _, symbol := range snapshot.Symbols() {
		for _, edge := range snapshot.OutgoingEdges(EdgeKindCall, symbol.ID) {
			if edge.Attributes.Metadata != nil {
				if edge.Attributes.Metadata[vulnType] == true {
					count++
				}
			}
		}
	}
	return count
}

// Helper function to check if specific vulnerability exists
func hasPythonVulnerability(pkg *IRPackage, vulnType string) bool {
	snapshot := pkg.Graph.Snapshot()
	for _, symbol := range snapshot.Symbols() {
		for _, edge := range snapshot.OutgoingEdges(EdgeKindCall, symbol.ID) {
			if edge.Attributes.Metadata != nil {
				if edge.Attributes.Metadata[vulnType] == true {
					return true
				}
			}
		}
	}
	return false
}

func TestPythonCommandInjection(t *testing.T) {
	// Create workspace with Python test files
	dir := t.TempDir()
	pythonContent := `
import os
import subprocess

def vulnerable_function():
    user_input = input("Enter command: ")
    os.system(f"ls {user_input}")
    subprocess.call(f"echo {user_input}", shell=True)
    subprocess.run([f"grep {user_input} file.txt"], shell=True)
`
	if err := os.WriteFile(filepath.Join(dir, "test.py"), []byte(pythonContent), 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	target := &Target{FS: os.DirFS(dir)}
	dialect := NewPythonDialect()

	// Test dialect support
	if !dialect.Supports(target) {
		t.Fatal("Python dialect should support Python files")
	}

	// Discover and prepare units
	units, err := dialect.DiscoverUnits(context.Background(), target)
	if err != nil {
		t.Fatalf("Failed to discover units: %v", err)
	}

	if len(units) == 0 {
		t.Fatal("Expected at least one compilation unit")
	}

	// Prepare the unit
	err = dialect.Prepare(context.Background(), units[0])
	if err != nil {
		t.Fatalf("Failed to prepare unit: %v", err)
	}

	// Lower to IR
	irPkg, err := dialect.LowerToIR(context.Background(), units[0])
	if err != nil {
		t.Fatalf("Failed to lower to IR: %v", err)
	}

	// Check for command injection vulnerabilities
	if !hasPythonVulnerability(irPkg, "command_injection") {
		t.Error("Expected to find command injection vulnerabilities")
	}

	count := countPythonVulnerabilities(irPkg, "command_injection")
	if count == 0 {
		t.Error("Expected at least one command injection vulnerability")
	}

	t.Logf("Found %d command injection vulnerabilities", count)
}

func TestPythonCodeInjection(t *testing.T) {
	dir := t.TempDir()
	pythonContent := `
def code_injection_example():
    user_code = input("Enter Python code: ")
    eval(user_code)
    exec(user_code)
    compile(user_code, '<string>', 'exec')
`
	if err := os.WriteFile(filepath.Join(dir, "code_injection.py"), []byte(pythonContent), 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	target := &Target{FS: os.DirFS(dir)}
	dialect := NewPythonDialect()

	units, err := dialect.DiscoverUnits(context.Background(), target)
	if err != nil {
		t.Fatalf("Failed to discover units: %v", err)
	}

	err = dialect.Prepare(context.Background(), units[0])
	if err != nil {
		t.Fatalf("Failed to prepare unit: %v", err)
	}

	irPkg, err := dialect.LowerToIR(context.Background(), units[0])
	if err != nil {
		t.Fatalf("Failed to lower to IR: %v", err)
	}

	if !hasPythonVulnerability(irPkg, "code_injection") {
		t.Error("Expected to find code injection vulnerabilities")
	}

	count := countPythonVulnerabilities(irPkg, "code_injection")
	t.Logf("Found %d code injection vulnerabilities", count)
}

func TestPythonSQLInjection(t *testing.T) {
	dir := t.TempDir()
	pythonContent := `
import sqlite3

def sql_example():
    user_id = input("Enter user ID: ")
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    cursor.executemany(f"INSERT INTO logs VALUES ('{user_id}')", [])
`
	if err := os.WriteFile(filepath.Join(dir, "sql_injection.py"), []byte(pythonContent), 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	target := &Target{FS: os.DirFS(dir)}
	dialect := NewPythonDialect()

	units, err := dialect.DiscoverUnits(context.Background(), target)
	if err != nil {
		t.Fatalf("Failed to discover units: %v", err)
	}

	err = dialect.Prepare(context.Background(), units[0])
	if err != nil {
		t.Fatalf("Failed to prepare unit: %v", err)
	}

	irPkg, err := dialect.LowerToIR(context.Background(), units[0])
	if err != nil {
		t.Fatalf("Failed to lower to IR: %v", err)
	}

	if !hasPythonVulnerability(irPkg, "sql_injection") {
		t.Error("Expected to find SQL injection vulnerabilities")
	}

	count := countPythonVulnerabilities(irPkg, "sql_injection")
	t.Logf("Found %d SQL injection vulnerabilities", count)
}

func TestPythonXSS(t *testing.T) {
	dir := t.TempDir()
	pythonContent := `
from flask import render_template, request
from django.http import HttpResponse

def xss_example():
    user_input = request.args.get('message')
    return render_template('page.html', message=user_input)
    return HttpResponse(f"<h1>Hello {user_input}</h1>")
    print(f"Debug: {user_input}")
`
	if err := os.WriteFile(filepath.Join(dir, "xss.py"), []byte(pythonContent), 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	target := &Target{FS: os.DirFS(dir)}
	dialect := NewPythonDialect()

	units, err := dialect.DiscoverUnits(context.Background(), target)
	if err != nil {
		t.Fatalf("Failed to discover units: %v", err)
	}

	err = dialect.Prepare(context.Background(), units[0])
	if err != nil {
		t.Fatalf("Failed to prepare unit: %v", err)
	}

	irPkg, err := dialect.LowerToIR(context.Background(), units[0])
	if err != nil {
		t.Fatalf("Failed to lower to IR: %v", err)
	}

	if !hasPythonVulnerability(irPkg, "xss") {
		t.Error("Expected to find XSS vulnerabilities")
	}

	count := countPythonVulnerabilities(irPkg, "xss")
	t.Logf("Found %d XSS vulnerabilities", count)
}

func TestPythonPathTraversal(t *testing.T) {
	dir := t.TempDir()
	pythonContent := `
import os
import shutil
from pathlib import Path

def path_example():
    filename = input("Enter filename: ")
    with open(f"/uploads/{filename}", 'r') as f:
        content = f.read()
    
    os.listdir(f"/var/log/{filename}")
    shutil.copy(filename, "/tmp/")
    Path(filename).read_text()
`
	if err := os.WriteFile(filepath.Join(dir, "path_traversal.py"), []byte(pythonContent), 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	target := &Target{FS: os.DirFS(dir)}
	dialect := NewPythonDialect()

	units, err := dialect.DiscoverUnits(context.Background(), target)
	if err != nil {
		t.Fatalf("Failed to discover units: %v", err)
	}

	err = dialect.Prepare(context.Background(), units[0])
	if err != nil {
		t.Fatalf("Failed to prepare unit: %v", err)
	}

	irPkg, err := dialect.LowerToIR(context.Background(), units[0])
	if err != nil {
		t.Fatalf("Failed to lower to IR: %v", err)
	}

	if !hasPythonVulnerability(irPkg, "path_traversal") {
		t.Error("Expected to find path traversal vulnerabilities")
	}

	count := countPythonVulnerabilities(irPkg, "path_traversal")
	t.Logf("Found %d path traversal vulnerabilities", count)
}

func TestPythonUnsafeDeserialization(t *testing.T) {
	dir := t.TempDir()
	pythonContent := `
import pickle
import yaml
import marshal

def deserialization_example():
    data = input("Enter serialized data: ")
    obj = pickle.loads(data)
    config = yaml.load(data)
    bytecode = marshal.loads(data)
`
	if err := os.WriteFile(filepath.Join(dir, "deserialization.py"), []byte(pythonContent), 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	target := &Target{FS: os.DirFS(dir)}
	dialect := NewPythonDialect()

	units, err := dialect.DiscoverUnits(context.Background(), target)
	if err != nil {
		t.Fatalf("Failed to discover units: %v", err)
	}

	err = dialect.Prepare(context.Background(), units[0])
	if err != nil {
		t.Fatalf("Failed to prepare unit: %v", err)
	}

	irPkg, err := dialect.LowerToIR(context.Background(), units[0])
	if err != nil {
		t.Fatalf("Failed to lower to IR: %v", err)
	}

	if !hasPythonVulnerability(irPkg, "unsafe_deserialization") {
		t.Error("Expected to find unsafe deserialization vulnerabilities")
	}

	count := countPythonVulnerabilities(irPkg, "unsafe_deserialization")
	t.Logf("Found %d unsafe deserialization vulnerabilities", count)
}

func TestPythonTaintSources(t *testing.T) {
	dir := t.TempDir()
	pythonContent := `
import os
import sys
from flask import request

def taint_sources():
    user_input = input("Enter data: ")
    env_var = os.environ.get('USER_CONFIG')
    cmd_arg = sys.argv[1] if len(sys.argv) > 1 else ""
    web_param = request.args.get('param')
    return user_input, env_var, cmd_arg, web_param
`
	if err := os.WriteFile(filepath.Join(dir, "taint_sources.py"), []byte(pythonContent), 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	target := &Target{FS: os.DirFS(dir)}
	dialect := NewPythonDialect()

	units, err := dialect.DiscoverUnits(context.Background(), target)
	if err != nil {
		t.Fatalf("Failed to discover units: %v", err)
	}

	err = dialect.Prepare(context.Background(), units[0])
	if err != nil {
		t.Fatalf("Failed to prepare unit: %v", err)
	}

	irPkg, err := dialect.LowerToIR(context.Background(), units[0])
	if err != nil {
		t.Fatalf("Failed to lower to IR: %v", err)
	}

	if !hasPythonVulnerability(irPkg, "taint_source") {
		t.Error("Expected to find taint sources")
	}

	count := countPythonVulnerabilities(irPkg, "taint_source")
	t.Logf("Found %d taint sources", count)
}

func TestPythonSanitizers(t *testing.T) {
	dir := t.TempDir()
	pythonContent := `
import html
import urllib.parse
import re

def sanitizer_example():
    user_input = input("Enter data: ")
    safe_html = html.escape(user_input)
    safe_url = urllib.parse.quote(user_input)
    safe_regex = re.escape(user_input)
    return safe_html, safe_url, safe_regex
`
	if err := os.WriteFile(filepath.Join(dir, "sanitizers.py"), []byte(pythonContent), 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	target := &Target{FS: os.DirFS(dir)}
	dialect := NewPythonDialect()

	units, err := dialect.DiscoverUnits(context.Background(), target)
	if err != nil {
		t.Fatalf("Failed to discover units: %v", err)
	}

	err = dialect.Prepare(context.Background(), units[0])
	if err != nil {
		t.Fatalf("Failed to prepare unit: %v", err)
	}

	irPkg, err := dialect.LowerToIR(context.Background(), units[0])
	if err != nil {
		t.Fatalf("Failed to lower to IR: %v", err)
	}

	if !hasPythonVulnerability(irPkg, "sanitizer") {
		t.Error("Expected to find sanitizers")
	}

	count := countPythonVulnerabilities(irPkg, "sanitizer")
	t.Logf("Found %d sanitizers", count)
}
