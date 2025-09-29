# Ruby SAST Test Cases

This directory contains comprehensive test cases for Ruby security analysis including:

## Vulnerability Categories

### Command Injection
- System calls with user input
- Backtick execution
- Kernel.system, exec, spawn
- Open pipe operations

### SQL Injection  
- ActiveRecord queries
- Raw SQL construction
- Dynamic where clauses
- String interpolation in queries

### Cross-Site Scripting (XSS)
- ERB template injection
- HTML output without sanitization
- JavaScript injection
- JSON output vulnerabilities

### Path Traversal
- File operations with user input
- Directory traversal patterns
- Zip slip vulnerabilities

### Code Injection
- eval() with user input
- instance_eval, class_eval
- Dynamic constant/method access
- YAML deserialization

### Insecure Deserialization
- Marshal.load
- YAML.load
- JSON.parse with unsafe options
- Pickle/Marshal vulnerabilities

### Rails-Specific
- Mass assignment vulnerabilities
- Weak parameter filtering
- CSRF bypass patterns
- Insecure direct object references

### Cryptographic Issues
- Weak random number generation
- Insecure hash algorithms
- Poor key management
- Weak encryption patterns

## Framework Coverage

- Rails (all major versions)
- Sinatra
- Rack applications
- Grape APIs
- Hanami
- Roda

## DSL Patterns

- RSpec/Minitest security test patterns
- Rake task security issues
- Gem security configurations
- Background job security (Sidekiq, Resque)