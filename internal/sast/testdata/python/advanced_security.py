# Additional Python Security Test Cases

import asyncio
import json
import pickle
import marshal
import dill
import yaml
import sys
import cgi
import urllib.parse
from pathlib import Path
import shutil

# Advanced command injection patterns
async def async_command_injection():
    user_cmd = input("Enter command: ")
    
    # Async subprocess patterns
    process = await asyncio.create_subprocess_shell(
        f"echo {user_cmd}",
        stdout=asyncio.subprocess.PIPE
    )
    
    # Different subprocess methods
    subprocess.check_output(f"ls {user_cmd}", shell=True)
    subprocess.check_call([f"cat {user_cmd}"], shell=True)

# More deserialization patterns
def advanced_deserialization():
    untrusted_data = sys.argv[1]
    
    # Various pickle methods
    pickle.load(open(untrusted_data, 'rb'))
    pickle.loads(untrusted_data.encode())
    
    # Other serialization libraries
    marshal.loads(untrusted_data)
    dill.loads(untrusted_data)
    yaml.load_all(untrusted_data)

# Path manipulation vulnerabilities
def path_manipulation():
    user_path = os.environ.get('USER_FILE')
    
    # Path operations
    full_path = os.path.join('/safe/dir', user_path)
    real_path = os.path.realpath(user_path)
    
    # Pathlib usage
    p = Path(user_path)
    p.read_text()
    
    # File operations
    shutil.copy(user_path, '/tmp/')
    shutil.move(user_path, '/backup/')

# JSON and data parsing
def json_parsing():
    json_data = request.get_json()
    
    # Safe JSON parsing (should not be flagged)
    parsed = json.loads(json_data)
    
    # But eval on JSON is dangerous
    eval(f"data = {json_data}")

# CGI and web input handling
def cgi_handling():
    form = cgi.FieldStorage()
    
    # CGI input sources
    user_data = form.getvalue('data')
    file_item = form['file']
    
    # Direct usage in sinks
    os.system(f"process {user_data}")

# URL encoding and security
def url_handling():
    url_param = urllib.parse.unquote(sys.argv[1])
    
    # Unescaped URL parameters can be dangerous
    eval(url_param)
    exec(url_param)

# Context managers and file operations
def context_managers():
    filename = input("File to read: ")
    
    # File operations in context managers
    with open(filename, 'r') as f:
        content = f.read()
    
    # Dynamic imports (code injection variant)
    module_name = input("Module to import: ")
    __import__(module_name)

# Class inheritance and method calls
class SecurityTestBase:
    def execute_user_command(self, cmd):
        return os.system(cmd)

class DerivedSecurity(SecurityTestBase):
    def process_data(self, data):
        # Inherited vulnerability
        return self.execute_user_command(data)

# Decorators and higher-order functions
def vulnerable_decorator(func):
    def wrapper(*args, **kwargs):
        user_input = args[0] if args else ""
        # Decorator adding vulnerability
        os.system(f"log {user_input}")
        return func(*args, **kwargs)
    return wrapper

@vulnerable_decorator
def decorated_function(data):
    return data.upper()

# List comprehensions and lambda functions
def functional_patterns():
    user_commands = [input(f"Command {i}: ") for i in range(3)]
    
    # List comprehension with vulnerability
    results = [os.system(cmd) for cmd in user_commands]
    
    # Lambda with vulnerability
    execute = lambda cmd: eval(cmd)
    execute(input("Python expression: "))

# Error handling and exceptions
def error_handling():
    try:
        user_code = input("Enter Python code: ")
        exec(user_code)
    except Exception as e:
        # Even in exception handling
        os.system(f"echo 'Error: {str(e)}'")

# Database connection patterns
def database_patterns():
    import sqlite3
    import pymongo
    
    user_query = request.args.get('query')
    
    # SQLite patterns
    conn = sqlite3.connect(':memory:')
    conn.execute(f"CREATE TABLE test AS {user_query}")
    
    # MongoDB patterns (NoSQL injection)
    client = pymongo.MongoClient()
    db = client.test_db
    collection = db.test_collection
    collection.find({"$where": user_query})

# Template injection
def template_injection():
    template_string = request.form.get('template')
    
    # Jinja2 template injection
    from jinja2 import Template
    template = Template(template_string)
    return template.render()

if __name__ == "__main__":
    print("Advanced Python security test cases")
    async_command_injection()
    advanced_deserialization()
    path_manipulation()
    json_parsing()
    cgi_handling()
    url_handling()
    context_managers()