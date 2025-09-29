# Python Security Vulnerabilities Test Cases

import os
import subprocess
import sqlite3
import pickle
import yaml
from flask import Flask, request, render_template
from django.http import HttpResponse
from django.shortcuts import render

app = Flask(__name__)

# Command Injection Vulnerabilities
def command_injection_examples():
    user_input = request.args.get('cmd')
    
    # Direct command execution - HIGH RISK
    os.system(f"ls {user_input}")
    os.popen(f"cat {user_input}").read()
    
    # Subprocess calls with shell=True - HIGH RISK  
    subprocess.call(f"echo {user_input}", shell=True)
    subprocess.run([f"grep {user_input} /etc/passwd"], shell=True)
    subprocess.Popen(f"find / -name {user_input}", shell=True)

# Code Injection Vulnerabilities
def code_injection_examples():
    user_code = request.form.get('code')
    user_expression = request.args.get('expr')
    
    # Dynamic code execution - CRITICAL RISK
    eval(user_expression)
    exec(user_code)
    compile(user_code, '<string>', 'exec')

# SQL Injection Vulnerabilities  
def sql_injection_examples():
    user_id = request.args.get('id')
    username = request.form.get('username')
    
    # Direct SQL query construction - HIGH RISK
    connection = sqlite3.connect('database.db')
    cursor = connection.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    cursor.execute(f"DELETE FROM users WHERE username = '{username}'")

# Cross-Site Scripting (XSS) Vulnerabilities
def xss_examples():
    user_message = request.args.get('message')
    user_name = request.form.get('name')
    
    # Unsafe template rendering - MEDIUM RISK
    return render_template('page.html', message=user_message)
    return HttpResponse(f"<h1>Hello {user_name}</h1>")
    
    # Direct output without escaping
    print(f"User input: {user_message}")

# Path Traversal Vulnerabilities
def path_traversal_examples():
    filename = request.args.get('file')
    directory = request.form.get('dir')
    
    # Unsafe file operations - HIGH RISK
    with open(f"/uploads/{filename}", 'r') as f:
        content = f.read()
    
    os.listdir(f"/var/log/{directory}")
    os.walk(f"/tmp/{directory}")

# Unsafe Deserialization Vulnerabilities
def unsafe_deserialization_examples():
    serialized_data = request.form.get('data')
    yaml_content = request.args.get('yaml')
    
    # Unsafe object reconstruction - CRITICAL RISK
    obj = pickle.loads(serialized_data)
    data = yaml.load(yaml_content)
    
# Taint Sources and Data Flow
def taint_source_examples():
    # Various input sources that should be tracked
    get_params = request.args.get('param')
    post_data = request.form.get('data')
    file_upload = request.files.get('file')
    headers = request.headers.get('X-Custom-Header')
    
    env_var = os.environ.get('USER_CONFIG')
    cmd_args = sys.argv[1] if len(sys.argv) > 1 else ""
    user_input = input("Enter data: ")
    
    return get_params, post_data, file_upload, headers, env_var, cmd_args, user_input

# Chained vulnerabilities showing data flow
def complex_vulnerability_chain():
    # Taint source
    user_data = request.args.get('data')
    
    # Potential path through multiple functions
    processed_data = process_user_input(user_data)
    
    # Multiple sinks in same function
    os.system(f"echo {processed_data}")  # Command injection
    eval(f"result = {processed_data}")   # Code injection
    
    cursor.execute(f"INSERT INTO logs VALUES ('{processed_data}')")  # SQL injection

def process_user_input(data):
    # Intermediate processing that maintains taint
    return data.upper()

# Class-based vulnerabilities
class UserManager:
    def __init__(self):
        self.db = sqlite3.connect('users.db')
    
    def get_user(self, user_id):
        # SQL injection in class method
        cursor = self.db.cursor()
        cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
        return cursor.fetchone()
    
    def execute_command(self, cmd):
        # Command injection in class method
        return os.system(cmd)

# Framework-specific patterns
@app.route('/user/<user_id>')
def get_user_profile(user_id):
    # Flask route with potential SQL injection
    cursor.execute(f"SELECT * FROM profiles WHERE user_id = {user_id}")
    return render_template('profile.html', user=cursor.fetchone())

@app.route('/search')
def search():
    query = request.args.get('q')
    # XSS through template rendering
    return render_template('results.html', query=query)

# Django-style views (simulated)
def django_view(request):
    user_input = request.GET.get('input')
    
    # Django HttpResponse XSS
    return HttpResponse(f"<p>You entered: {user_input}</p>")

# Main execution
if __name__ == "__main__":
    # Entry point detection
    main()
    
def main():
    print("Python security analysis test application")
    command_injection_examples()
    code_injection_examples()
    sql_injection_examples()
    xss_examples()
    path_traversal_examples()
    unsafe_deserialization_examples()