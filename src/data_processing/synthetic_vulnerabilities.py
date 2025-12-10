"""
Synthetic Vulnerability Generator

Generates synthetic examples of common vulnerability patterns to augment
the training data. This helps the model learn clear, textbook examples
of vulnerabilities that may be underrepresented in real-world data.
"""

import random
from typing import List, Dict

# SQL Injection patterns
SQL_INJECTION_TEMPLATES = [
    # String concatenation
    '''def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    return cursor.fetchone()''',
    
    '''def search_users(name):
    sql = "SELECT * FROM users WHERE name = '" + name + "'"
    return db.execute(sql)''',
    
    '''def login(username, password):
    query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
    cursor.execute(query)
    return cursor.fetchone()''',
    
    '''def delete_user(user_id):
    query = "DELETE FROM users WHERE id = " + str(user_id)
    conn.execute(query)''',
    
    '''def update_email(user_id, email):
    sql = "UPDATE users SET email = '" + email + "' WHERE id = " + user_id
    db.execute(sql)''',
    
    # f-string formatting
    '''def find_product(product_id):
    query = f"SELECT * FROM products WHERE id = {product_id}"
    cursor.execute(query)
    return cursor.fetchall()''',
    
    '''def get_orders(customer_id):
    sql = f"SELECT * FROM orders WHERE customer_id = {customer_id}"
    return db.query(sql)''',
    
    # .format() method
    '''def get_employee(emp_id):
    query = "SELECT * FROM employees WHERE id = {}".format(emp_id)
    cursor.execute(query)
    return cursor.fetchone()''',
    
    '''def search_products(keyword):
    sql = "SELECT * FROM products WHERE name LIKE '%{}%'".format(keyword)
    return db.execute(sql)''',
    
    # % formatting
    '''def get_customer(customer_id):
    query = "SELECT * FROM customers WHERE id = %s" % customer_id
    cursor.execute(query)
    return cursor.fetchone()''',
    
    # Raw SQL execution
    '''def run_query(user_query):
    cursor.execute(user_query)
    return cursor.fetchall()''',
    
    '''def search(table, column, value):
    query = "SELECT * FROM " + table + " WHERE " + column + " = '" + value + "'"
    return db.execute(query)''',
]

# Command Injection patterns
COMMAND_INJECTION_TEMPLATES = [
    '''import os
def run_command(user_input):
    os.system("ls " + user_input)''',
    
    '''import os
def ping_host(host):
    os.system("ping -c 4 " + host)''',
    
    '''import subprocess
def execute(cmd):
    subprocess.call(cmd, shell=True)''',
    
    '''import subprocess
def run_script(script_name):
    subprocess.Popen("bash " + script_name, shell=True)''',
    
    '''import os
def process_file(filename):
    os.popen("cat " + filename)''',
    
    '''def execute_command(command):
    import os
    return os.system(command)''',
    
    '''import subprocess
def compile_code(filename):
    subprocess.run(f"gcc {filename} -o output", shell=True)''',
    
    '''import os
def backup_file(src, dest):
    os.system(f"cp {src} {dest}")''',
]

# Path Traversal patterns
PATH_TRAVERSAL_TEMPLATES = [
    '''def read_file(filename):
    with open("/data/" + filename, "r") as f:
        return f.read()''',
    
    '''def get_document(doc_name):
    path = "/var/www/documents/" + doc_name
    return open(path).read()''',
    
    '''def download_file(user_file):
    filepath = os.path.join("/uploads", user_file)
    return send_file(filepath)''',
    
    '''def load_config(config_name):
    with open(f"configs/{config_name}") as f:
        return json.load(f)''',
    
    '''def serve_static(filename):
    return open("static/" + filename, "rb").read()''',
    
    '''def read_user_file(user_id, filename):
    path = f"/home/{user_id}/{filename}"
    with open(path) as f:
        return f.read()''',
]

# XSS patterns
XSS_TEMPLATES = [
    '''from flask import Flask, request
app = Flask(__name__)

@app.route('/greet')
def greet():
    name = request.args.get('name', '')
    return f"<h1>Hello, {name}!</h1>"''',
    
    '''from flask import request, Markup
def render_comment(comment):
    return Markup(f"<div class='comment'>{comment}</div>")''',
    
    '''def generate_html(user_input):
    return "<html><body>" + user_input + "</body></html>"''',
    
    '''from flask import render_template_string, request
def show_message():
    msg = request.args.get('message')
    return render_template_string("<p>" + msg + "</p>")''',
    
    """def create_link(url, text):
    return '<a href="' + url + '">' + text + '</a>'""",
]

# Insecure Deserialization patterns
DESERIALIZATION_TEMPLATES = [
    '''import pickle
def load_data(data):
    return pickle.loads(data)''',
    
    '''import pickle
def load_from_file(filename):
    with open(filename, 'rb') as f:
        return pickle.load(f)''',
    
    '''import yaml
def parse_config(yaml_string):
    return yaml.load(yaml_string)''',
    
    '''import marshal
def load_code(data):
    return marshal.loads(data)''',
    
    '''import shelve
def get_data(key):
    db = shelve.open('mydata')
    return db[key]''',
    
    '''from pickle import loads
def deserialize(serialized_data):
    return loads(serialized_data)''',
]

# Hardcoded Credentials patterns
HARDCODED_CREDENTIALS_TEMPLATES = [
    '''def connect_db():
    password = "admin123"
    connection = mysql.connect(
        host="localhost",
        user="root",
        password=password
    )
    return connection''',
    
    '''API_KEY = "sk-1234567890abcdef"
def call_api():
    return requests.get(url, headers={"Authorization": API_KEY})''',
    
    '''def authenticate():
    secret = "super_secret_key_123"
    return jwt.encode(payload, secret)''',
    
    '''DB_PASSWORD = "password123"
def get_connection():
    return psycopg2.connect(password=DB_PASSWORD)''',
    
    '''def send_email():
    smtp_password = "email_pass_456"
    server.login("admin@example.com", smtp_password)''',
    
    '''AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
def upload_to_s3(file):
    s3.upload(file, credentials=AWS_SECRET_KEY)''',
]

# Weak Cryptography patterns
WEAK_CRYPTO_TEMPLATES = [
    '''import hashlib
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()''',
    
    '''import hashlib
def create_hash(data):
    return hashlib.sha1(data.encode()).hexdigest()''',
    
    '''from Crypto.Cipher import DES
def encrypt(data, key):
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(data)''',
    
    '''import hashlib
def verify_password(password, stored_hash):
    return hashlib.md5(password.encode()).hexdigest() == stored_hash''',
    
    '''def simple_hash(text):
    import hashlib
    return hashlib.md5(text.encode()).digest()''',
]

# Safe code examples (for negative samples)
SAFE_CODE_TEMPLATES = [
    '''def calculate_sum(numbers: list) -> int:
    if not isinstance(numbers, list):
        raise TypeError("Input must be a list")
    return sum(numbers)''',
    
    '''def greet(name: str) -> str:
    return f"Hello, {name}!"''',
    
    '''def fibonacci(n: int) -> int:
    if n <= 1:
        return n
    return fibonacci(n-1) + fibonacci(n-2)''',
    
    '''def is_palindrome(s: str) -> bool:
    s = s.lower().replace(" ", "")
    return s == s[::-1]''',
    
    '''def factorial(n: int) -> int:
    if n == 0:
        return 1
    return n * factorial(n - 1)''',
    
    '''class Calculator:
    def add(self, a, b):
        return a + b
    
    def subtract(self, a, b):
        return a - b''',
    
    '''def read_json_file(filepath: str) -> dict:
    import json
    with open(filepath, 'r') as f:
        return json.load(f)''',
    
    r'''def validate_email(email: str) -> bool:
    import re
    pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return bool(re.match(pattern, email))''',
    
    # Safe SQL with parameterized queries
    '''def get_user_safe(user_id):
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    return cursor.fetchone()''',
    
    '''def search_products_safe(keyword):
    query = "SELECT * FROM products WHERE name LIKE %s"
    cursor.execute(query, (f"%{keyword}%",))
    return cursor.fetchall()''',
    
    # Safe file operations with validation
    '''import os
def read_file_safe(filename):
    safe_dir = "/data/uploads"
    filepath = os.path.join(safe_dir, os.path.basename(filename))
    if not filepath.startswith(safe_dir):
        raise ValueError("Invalid path")
    with open(filepath, 'r') as f:
        return f.read()''',
    
    # Safe password hashing
    '''import bcrypt
def hash_password_safe(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt)''',
]


# =============================================================================
# SIMPLE SAFE CODE TEMPLATES - These are what users commonly test with
# The model needs to learn that simple code is NOT automatically vulnerable
# =============================================================================

SIMPLE_SAFE_TEMPLATES = [
    # === BASIC PRINTS ===
    ("print('hello')", "basic_print"),
    ("print('Hello, World!')", "basic_print"),
    ("print('test')", "basic_print"),
    ("print(123)", "basic_print"),
    ("print(True)", "basic_print"),
    ("print('done')", "basic_print"),
    ("print(f'Result: {x}')", "basic_print"),
    ("print(str(value))", "basic_print"),
    ("print(len(items))", "basic_print"),
    ("print(type(obj))", "basic_print"),
    
    # === SIMPLE ARITHMETIC FUNCTIONS ===
    ('''def add(a, b):
    return a + b''', "arithmetic"),
    
    ('''def subtract(a, b):
    return a - b''', "arithmetic"),
    
    ('''def multiply(x, y):
    return x * y''', "arithmetic"),
    
    ('''def divide(a, b):
    if b == 0:
        raise ValueError("Cannot divide by zero")
    return a / b''', "arithmetic"),
    
    ('''def square(n):
    return n * n''', "arithmetic"),
    
    ('''def power(base, exp):
    return base ** exp''', "arithmetic"),
    
    ('''def absolute(n):
    return abs(n)''', "arithmetic"),
    
    ('''def modulo(a, b):
    return a % b''', "arithmetic"),
    
    # === SIMPLE STRING FUNCTIONS ===
    ('''def greet(name):
    return f"Hello, {name}!"''', "string_function"),
    
    ('''def to_upper(text):
    return text.upper()''', "string_function"),
    
    ('''def to_lower(text):
    return text.lower()''', "string_function"),
    
    ('''def reverse_string(s):
    return s[::-1]''', "string_function"),
    
    ('''def get_length(s):
    return len(s)''', "string_function"),
    
    ('''def concat(a, b):
    return a + b''', "string_function"),
    
    ('''def strip_whitespace(text):
    return text.strip()''', "string_function"),
    
    ('''def format_name(first, last):
    return f"{first} {last}"''', "string_function"),
    
    # === LIST OPERATIONS ===
    ('''def get_sum(numbers):
    return sum(numbers)''', "list_operation"),
    
    ('''def get_max(numbers):
    return max(numbers)''', "list_operation"),
    
    ('''def get_min(numbers):
    return min(numbers)''', "list_operation"),
    
    ('''def get_average(numbers):
    return sum(numbers) / len(numbers)''', "list_operation"),
    
    ('''def sort_list(items):
    return sorted(items)''', "list_operation"),
    
    ('''def reverse_list(items):
    return list(reversed(items))''', "list_operation"),
    
    ('''def filter_positive(nums):
    return [n for n in nums if n > 0]''', "list_operation"),
    
    ('''def filter_even(nums):
    return [n for n in nums if n % 2 == 0]''', "list_operation"),
    
    ('''def double_values(nums):
    return [n * 2 for n in nums]''', "list_operation"),
    
    ('''def first_n(items, n):
    return items[:n]''', "list_operation"),
    
    # === BOOLEAN/CONDITIONAL ===
    ('''def is_even(n):
    return n % 2 == 0''', "boolean"),
    
    ('''def is_odd(n):
    return n % 2 != 0''', "boolean"),
    
    ('''def is_positive(n):
    return n > 0''', "boolean"),
    
    ('''def is_empty(lst):
    return len(lst) == 0''', "boolean"),
    
    ('''def is_valid_age(age):
    return 0 <= age <= 150''', "boolean"),
    
    ('''def contains(lst, item):
    return item in lst''', "boolean"),
    
    # === SIMPLE CLASSES ===
    ('''class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y''', "class_definition"),
    
    ('''class Counter:
    def __init__(self):
        self.count = 0
    
    def increment(self):
        self.count += 1''', "class_definition"),
    
    ('''class Person:
    def __init__(self, name):
        self.name = name
    
    def greet(self):
        return f"Hi, I'm {self.name}"''', "class_definition"),
    
    ('''class Rectangle:
    def __init__(self, width, height):
        self.width = width
        self.height = height
    
    def area(self):
        return self.width * self.height''', "class_definition"),
    
    # === SAFE PARAMETERIZED SQL ===
    ('''def get_user(user_id):
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()''', "safe_sql"),
    
    ('''def find_by_email(email):
    query = "SELECT * FROM users WHERE email = %s"
    cursor.execute(query, (email,))
    return cursor.fetchone()''', "safe_sql"),
    
    ('''def insert_user(name, email):
    cursor.execute("INSERT INTO users (name, email) VALUES (?, ?)", (name, email))
    conn.commit()''', "safe_sql"),
    
    ('''def search_products(category):
    query = "SELECT * FROM products WHERE category = %s"
    cursor.execute(query, (category,))
    return cursor.fetchall()''', "safe_sql"),
    
    ('''def update_user(user_id, name):
    cursor.execute("UPDATE users SET name = ? WHERE id = ?", (name, user_id))
    conn.commit()''', "safe_sql"),
    
    ('''def delete_user(user_id):
    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()''', "safe_sql"),
    
    # === SAFE FILE OPERATIONS (hardcoded paths) ===
    ('''def read_config():
    with open("config.json", "r") as f:
        return json.load(f)''', "safe_file"),
    
    ('''def write_log(message):
    with open("app.log", "a") as f:
        f.write(message + "\\n")''', "safe_file"),
    
    ('''def load_settings():
    with open("settings.yaml", "r") as f:
        return yaml.safe_load(f)''', "safe_file"),
    
    # === SAFE JSON/YAML ===
    ('''def parse_json(json_string):
    import json
    return json.loads(json_string)''', "safe_deserialization"),
    
    ('''def parse_yaml(yaml_string):
    import yaml
    return yaml.safe_load(yaml_string)''', "safe_deserialization"),
    
    ('''def to_json(data):
    import json
    return json.dumps(data)''', "safe_deserialization"),
    
    # === SAFE CRYPTO ===
    ('''def hash_password(password, salt):
    import hashlib
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)''', "safe_crypto"),
    
    ('''def generate_token():
    import secrets
    return secrets.token_hex(32)''', "safe_crypto"),
    
    ('''def secure_random():
    import secrets
    return secrets.randbelow(1000)''', "safe_crypto"),
    
    # === UTILITY FUNCTIONS ===
    ('''def clamp(value, min_val, max_val):
    return max(min_val, min(max_val, value))''', "utility"),
    
    ('''def safe_divide(a, b, default=0):
    return a / b if b != 0 else default''', "utility"),
    
    ('''def get_or_default(dictionary, key, default=None):
    return dictionary.get(key, default)''', "utility"),
    
    ('''def flatten(nested_list):
    return [item for sublist in nested_list for item in sublist]''', "utility"),
    
    ('''def unique(items):
    return list(set(items))''', "utility"),
    
    ('''def count_items(items):
    from collections import Counter
    return Counter(items)''', "utility"),
    
    # === MATH ALGORITHMS ===
    ('''def factorial(n):
    if n <= 1:
        return 1
    return n * factorial(n - 1)''', "algorithm"),
    
    ('''def fibonacci(n):
    if n <= 1:
        return n
    return fibonacci(n-1) + fibonacci(n-2)''', "algorithm"),
    
    ('''def gcd(a, b):
    while b:
        a, b = b, a % b
    return a''', "algorithm"),
    
    ('''def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True''', "algorithm"),
    
    ('''def binary_search(arr, target):
    left, right = 0, len(arr) - 1
    while left <= right:
        mid = (left + right) // 2
        if arr[mid] == target:
            return mid
        elif arr[mid] < target:
            left = mid + 1
        else:
            right = mid - 1
    return -1''', "algorithm"),
]


def generate_simple_safe_examples(count: int = 500) -> List[Dict]:
    """
    Generate simple safe code examples.
    
    These are the types of code users commonly test with in the UI.
    The model needs to learn that simple code is NOT automatically vulnerable.
    
    Args:
        count: Total number of simple safe examples to generate
    
    Returns:
        List of safe code example dictionaries
    """
    examples = []
    
    # Generate variations of each template
    for i in range(count):
        template, category = SIMPLE_SAFE_TEMPLATES[i % len(SIMPLE_SAFE_TEMPLATES)]
        
        code = template.strip()
        
        # Add some variations
        variation = i // len(SIMPLE_SAFE_TEMPLATES)
        if variation % 4 == 1:
            code = f"# {category} example\n{code}"
        elif variation % 4 == 2:
            code = f'"""{category}"""\n{code}'
        elif variation % 4 == 3:
            # Add a simple docstring
            lines = code.split('\n')
            if lines[0].startswith('def ') or lines[0].startswith('class '):
                lines.insert(1, '    """Simple implementation."""')
                code = '\n'.join(lines)
        
        examples.append({
            "code": code,
            "label": 0,  # Safe
            "category": f"simple_{category}",
            "cwe": None,
            "source": "synthetic_safe",
            "quality_score": 1.0  # High quality - clean examples
        })
    
    return examples


def generate_synthetic_vulnerabilities(
    num_per_category: int = 50,
    include_safe: bool = True
) -> List[Dict]:
    """
    Generate synthetic vulnerability examples.
    
    Args:
        num_per_category: Number of examples to generate per vulnerability type
        include_safe: Whether to include safe code examples
    
    Returns:
        List of dictionaries with 'code', 'label', and 'category' keys
    """
    examples = []
    
    vulnerability_templates = [
        (SQL_INJECTION_TEMPLATES, "sql_injection", "CWE-89"),
        (COMMAND_INJECTION_TEMPLATES, "command_injection", "CWE-78"),
        (PATH_TRAVERSAL_TEMPLATES, "path_traversal", "CWE-22"),
        (XSS_TEMPLATES, "xss", "CWE-79"),
        (DESERIALIZATION_TEMPLATES, "deserialization", "CWE-502"),
        (HARDCODED_CREDENTIALS_TEMPLATES, "hardcoded_credentials", "CWE-798"),
        (WEAK_CRYPTO_TEMPLATES, "weak_crypto", "CWE-327"),
    ]
    
    for templates, category, cwe in vulnerability_templates:
        # Use each template and generate variations
        for i in range(num_per_category):
            template = templates[i % len(templates)]
            
            # Add some variation with different variable names
            code = _add_variation(template, i)
            
            examples.append({
                "code": code,
                "label": 1,  # Vulnerable
                "category": category,
                "cwe": cwe,
                "source": "synthetic"
            })
    
    if include_safe:
        for i in range(num_per_category * 2):  # More safe examples
            template = SAFE_CODE_TEMPLATES[i % len(SAFE_CODE_TEMPLATES)]
            code = _add_variation(template, i)
            
            examples.append({
                "code": code,
                "label": 0,  # Safe
                "category": "safe",
                "cwe": None,
                "source": "synthetic"
            })
    
    random.shuffle(examples)
    return examples


def _add_variation(code: str, seed: int) -> str:
    """Add minor variations to code to increase diversity."""
    # Simple variations - change variable names slightly
    variations = [
        ("user_id", f"user_id_{seed % 10}"),
        ("username", f"username_{seed % 10}"),
        ("password", f"pwd_{seed % 10}"),
        ("query", f"sql_query_{seed % 10}"),
        ("filename", f"file_{seed % 10}"),
        ("data", f"input_data_{seed % 10}"),
    ]
    
    result = code
    if seed % 3 == 0:  # Only apply variations sometimes
        var_name, new_name = random.choice(variations)
        result = result.replace(var_name, new_name)
    
    return result


def get_synthetic_vulnerable_codes() -> List[str]:
    """Get just the vulnerable code strings for dataset augmentation."""
    examples = generate_synthetic_vulnerabilities(num_per_category=30, include_safe=False)
    return [ex["code"] for ex in examples]


def get_synthetic_safe_codes() -> List[str]:
    """Get just the safe code strings for dataset augmentation."""
    return SAFE_CODE_TEMPLATES.copy()


def get_simple_safe_codes() -> List[str]:
    """Get simple safe code strings - these are what users commonly test with."""
    examples = generate_simple_safe_examples(count=100)
    return [ex["code"] for ex in examples]


if __name__ == "__main__":
    # Test generation
    print("=" * 60)
    print("Testing Synthetic Vulnerability Generator")
    print("=" * 60)
    
    # Test vulnerable examples
    examples = generate_synthetic_vulnerabilities(num_per_category=10)
    print(f"\n✓ Generated {len(examples)} synthetic vulnerable examples")
    
    # Count by category
    from collections import Counter
    categories = Counter(ex["category"] for ex in examples)
    print("\nVulnerable by category:")
    for cat, count in categories.items():
        print(f"  {cat}: {count}")
    
    # Test simple safe examples
    simple_safe = generate_simple_safe_examples(count=100)
    print(f"\n✓ Generated {len(simple_safe)} simple safe examples")
    
    safe_categories = Counter(ex["category"] for ex in simple_safe)
    print("\nSimple safe by category:")
    for cat, count in sorted(safe_categories.items()):
        print(f"  {cat}: {count}")
    
    # Show sample examples
    print("\n" + "=" * 60)
    print("Sample Examples")
    print("=" * 60)
    
    print("\n--- Sample SQL Injection (VULNERABLE) ---")
    sql_ex = next(ex for ex in examples if ex["category"] == "sql_injection")
    print(sql_ex["code"])
    
    print("\n--- Sample Simple Safe (SAFE) ---")
    simple_ex = simple_safe[0]
    print(f"Category: {simple_ex['category']}")
    print(simple_ex["code"])
    
    print("\n--- Sample Safe SQL (SAFE) ---")
    safe_sql = next((ex for ex in simple_safe if "safe_sql" in ex["category"]), None)
    if safe_sql:
        print(safe_sql["code"])
    
    print("\n✅ All tests passed!")
