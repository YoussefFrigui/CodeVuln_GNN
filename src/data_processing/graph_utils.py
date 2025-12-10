"""
Graph Utilities for Code Representation

This module provides functions for converting Python source code into graph
representations suitable for Graph Neural Network (GNN) models. It focuses
on parsing Abstract Syntax Trees (ASTs) and converting them into NetworkX
graphs, which can then be transformed into PyTorch Geometric data objects.

Enhanced with semantic features for better vulnerability detection:
- Function/method name hashing
- Dangerous function detection
- String operation detection
- User input source detection
"""

import ast
import re
import hashlib
import warnings
from typing import Dict, Any, Tuple, List, Optional, Set

# Suppress SyntaxWarning for invalid escape sequences in parsed code
# These are common in regex patterns and don't affect parsing
warnings.filterwarnings('ignore', category=SyntaxWarning)

import networkx as nx
import torch
from torch_geometric.data import Data
from torch_geometric.utils import from_networkx

# A comprehensive mapping of AST node types to integer identifiers.
# This is used to create one-hot encodings for node features.
NODE_TYPES: Dict[str, int] = {
    "Module": 0, "FunctionDef": 1, "ClassDef": 2, "Return": 3, "Assign": 4,
    "If": 5, "For": 6, "While": 7, "Call": 8, "Name": 9, "Constant": 10,
    "BinOp": 11, "Compare": 12, "List": 13, "Dict": 14, "Attribute": 15,
    "Expr": 16, "Import": 17, "ImportFrom": 18, "With": 19, "Try": 20,
    "ExceptHandler": 21, "Raise": 22, "Assert": 23, "Delete": 24, "AugAssign": 25,
    "AnnAssign": 26, "AsyncFunctionDef": 27, "AsyncFor": 28, "AsyncWith": 29,
    "Await": 30, "Yield": 31, "YieldFrom": 32, "Global": 33, "Nonlocal": 34,
    "Pass": 35, "Break": 36, "Continue": 37, "Slice": 38, "ExtSlice": 39,
    "Index": 40, "Lambda": 41, "Ellipsis": 42, "Starred": 43, "Set": 44,
    "SetComp": 45, "DictComp": 46, "ListComp": 47, "GeneratorExp": 48,
}
# Add a default for unknown node types
UNKNOWN_NODE_TYPE: int = len(NODE_TYPES)

# =============================================================================
# DANGEROUS FUNCTION/PATTERN DEFINITIONS
# =============================================================================

# Dangerous functions that can lead to code execution
DANGEROUS_EXEC_FUNCTIONS: Set[str] = {
    # Python built-ins
    'eval', 'exec', 'compile', '__import__',
    # OS command execution
    'system', 'popen', 'popen2', 'popen3', 'popen4',
    'spawn', 'spawnl', 'spawnle', 'spawnlp', 'spawnlpe',
    'spawnv', 'spawnve', 'spawnvp', 'spawnvpe',
    'execl', 'execle', 'execlp', 'execlpe',
    'execv', 'execve', 'execvp', 'execvpe',
    # Subprocess
    'call', 'check_call', 'check_output', 'run', 'Popen',
}

# Dangerous deserialization functions
DANGEROUS_DESERIALIZE_FUNCTIONS: Set[str] = {
    # Pickle
    'loads', 'load', 'Unpickler',
    # YAML (unsafe)
    'unsafe_load', 'full_load',
    # Other
    'marshal.loads', 'marshal.load',
}

# Modules that make deserialization dangerous
DANGEROUS_DESERIALIZE_MODULES: Set[str] = {
    'pickle', 'cPickle', '_pickle', 'dill', 'shelve',
    'yaml', 'marshal',
}

# SQL-related functions (potential injection)
SQL_FUNCTIONS: Set[str] = {
    'execute', 'executemany', 'executescript',
    'raw', 'extra', 'RawSQL',
}

# Weak cryptography
WEAK_CRYPTO_FUNCTIONS: Set[str] = {
    'md5', 'sha1', 'md4', 'md2',
}

# Path/file operations that could be dangerous with user input
DANGEROUS_FILE_FUNCTIONS: Set[str] = {
    'open', 'file', 'read', 'write', 'readlines',
    'makedirs', 'mkdir', 'rmdir', 'remove', 'unlink',
    'rename', 'replace', 'chmod', 'chown',
}

# Network functions
DANGEROUS_NETWORK_FUNCTIONS: Set[str] = {
    'urlopen', 'urlretrieve', 'Request',
    'get', 'post', 'put', 'delete', 'patch',  # requests library
    'connect', 'socket',
}

# XSS-related (template rendering without escaping)
XSS_FUNCTIONS: Set[str] = {
    'Markup', 'SafeString', 'mark_safe',
    'format_html', 'render_to_string',
}

# User input sources
USER_INPUT_SOURCES: Set[str] = {
    # Flask/Django
    'request', 'args', 'form', 'values', 'data', 'json',
    'GET', 'POST', 'REQUEST', 'COOKIES', 'FILES',
    # General
    'input', 'raw_input', 'stdin', 'argv',
    'environ', 'getenv',
}

# String operations that might indicate concatenation vulnerabilities
STRING_OPERATIONS: Set[str] = {
    'format', 'join', 'replace', 'split',
    '%', '+',  # operators
}

# =============================================================================
# FEATURE EXTRACTION HELPERS
# =============================================================================

def _hash_name(name: str, buckets: int = 100) -> float:
    """Hash a name to a bucket number (normalized 0-1). Uses simple hash for speed."""
    if not name:
        return 0.0
    # Use Python's built-in hash (fast) instead of MD5
    return (hash(name) % buckets) / buckets

def _get_full_attr_name(node: ast.AST) -> str:
    """
    Extract the full attribute chain from an AST node.
    e.g., for `os.path.join`, returns 'os.path.join'
    """
    parts = []
    current = node
    
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    
    if isinstance(current, ast.Name):
        parts.append(current.id)
    
    return '.'.join(reversed(parts))

def _get_call_name(node: ast.Call) -> Tuple[str, str]:
    """
    Extract function name and module from a Call node.
    Returns (function_name, full_path)
    """
    if isinstance(node.func, ast.Name):
        # Direct function call: eval(), exec()
        return node.func.id, node.func.id
    elif isinstance(node.func, ast.Attribute):
        # Method/attribute call: os.system(), pickle.loads()
        func_name = node.func.attr
        full_path = _get_full_attr_name(node.func)
        return func_name, full_path
    return '', ''

def _is_dangerous_call(func_name: str, full_path: str) -> Tuple[bool, int]:
    """
    Check if a function call is dangerous.
    Returns (is_dangerous, danger_category)
    
    Danger categories:
    0 = not dangerous
    1 = code execution (eval, exec, os.system)
    2 = deserialization (pickle.loads, yaml.load)
    3 = SQL operations
    4 = weak crypto
    5 = file operations
    6 = network operations
    7 = XSS-related
    """
    # Check for code execution
    if func_name in DANGEROUS_EXEC_FUNCTIONS:
        return True, 1
    
    # Check for dangerous deserialization
    if func_name in DANGEROUS_DESERIALIZE_FUNCTIONS:
        # Check if it's from a dangerous module
        for module in DANGEROUS_DESERIALIZE_MODULES:
            if module in full_path:
                return True, 2
    
    # Check for SQL
    if func_name in SQL_FUNCTIONS:
        return True, 3
    
    # Check for weak crypto
    if func_name in WEAK_CRYPTO_FUNCTIONS:
        return True, 4
    
    # Check for file operations
    if func_name in DANGEROUS_FILE_FUNCTIONS:
        return True, 5
    
    # Check for network operations
    if func_name in DANGEROUS_NETWORK_FUNCTIONS:
        return True, 6
    
    # Check for XSS
    if func_name in XSS_FUNCTIONS:
        return True, 7
    
    return False, 0

def _is_user_input(name: str) -> bool:
    """Check if a name looks like user input."""
    name_lower = name.lower()
    return any(src in name_lower for src in USER_INPUT_SOURCES)

def _has_string_concat(node: ast.AST) -> bool:
    """Check if node involves string concatenation."""
    if isinstance(node, ast.BinOp):
        if isinstance(node.op, ast.Add):
            # Check if either side is a string
            for operand in [node.left, node.right]:
                if isinstance(operand, ast.Constant) and isinstance(operand.value, str):
                    return True
                if isinstance(operand, ast.JoinedStr):  # f-string
                    return True
    return False


def fix_incomplete_code(code: str) -> Optional[str]:
    """
    Attempt to fix incomplete Python code snippets to make them parseable.
    
    Many code snippets from security advisories are partial - missing imports,
    incomplete functions, or just code fragments. This function tries various
    strategies to make them parseable while preserving the vulnerability pattern.
    
    Args:
        code: The potentially incomplete Python code
        
    Returns:
        Fixed code string if successful, None if unfixable
    """
    if not code or not code.strip():
        return None
    
    code = code.strip()
    
    # Pre-processing: Remove doctest examples (>>> lines)
    if '>>>' in code:
        lines = code.split('\n')
        code = '\n'.join(line for line in lines if not line.strip().startswith('>>>') and not line.strip().startswith('...'))
        code = code.strip()
        if not code:
            return None
    
    # Pre-processing: Remove unterminated triple-quoted strings at the end
    code = re.sub(r'"""[^"]*$', '"""pass"""', code)
    code = re.sub(r"'''[^']*$", "'''pass'''", code)
    
    # Pre-processing: Fix trailing backslashes (line continuations)
    if code.rstrip().endswith('\\'):
        code = code.rstrip().rstrip('\\') + ' None'
    
    # Pre-processing: Remove leading unmatched brackets/parens (code fragments)
    while code and code[0] in ')]}':
        code = code[1:].strip()
    
    # Pre-processing: Remove orphan decorators at the end
    lines = code.split('\n')
    while lines and lines[-1].strip().startswith('@'):
        lines = lines[:-1]
    code = '\n'.join(lines)
    
    # Pre-processing: Fix code that starts with indented content
    # by removing leading whitespace consistently
    lines = code.split('\n')
    if lines and lines[0].startswith((' ', '\t')):
        # Find minimum indentation
        min_indent = float('inf')
        for line in lines:
            if line.strip():
                indent = len(line) - len(line.lstrip())
                min_indent = min(min_indent, indent)
        if min_indent > 0 and min_indent != float('inf'):
            lines = [line[min_indent:] if len(line) >= min_indent else line for line in lines]
            code = '\n'.join(lines)
    
    # Strategy 1: Try parsing as-is first
    try:
        ast.parse(code)
        return code
    except SyntaxError:
        pass
    
    # Strategy 2: Balance brackets - add missing closing brackets
    try:
        fixed = _balance_brackets(code)
        ast.parse(fixed)
        return fixed
    except SyntaxError:
        pass
    
    # Strategy 3: Wrap in a function if it looks like function body
    # (indented code or statements without function def)
    try:
        wrapped = f"def _wrapper():\n" + "\n".join(f"    {line}" for line in code.split("\n"))
        ast.parse(wrapped)
        return wrapped
    except SyntaxError:
        pass
    
    # Strategy 4: Add pass statement to incomplete blocks
    try:
        fixed = code
        # Add pass to empty blocks
        fixed = re.sub(r'(:\s*)$', r'\1\n    pass', fixed, flags=re.MULTILINE)
        ast.parse(fixed)
        return fixed
    except SyntaxError:
        pass
    
    # Strategy 5: Remove problematic lines (like partial statements)
    lines = code.split('\n')
    for i in range(len(lines), 0, -1):
        try:
            partial = '\n'.join(lines[:i])
            ast.parse(partial)
            if len(partial.strip()) > 20:  # Make sure we have enough code
                return partial
        except SyntaxError:
            continue
    
    # Strategy 6: Wrap everything in try-except to handle partial code
    try:
        wrapped = f"try:\n" + "\n".join(f"    {line}" for line in code.split("\n")) + "\nexcept:\n    pass"
        ast.parse(wrapped)
        return wrapped
    except SyntaxError:
        pass
    
    # Strategy 7: Extract only the lines that look like valid Python
    valid_lines = []
    for line in lines:
        line_stripped = line.strip()
        if not line_stripped or line_stripped.startswith('#'):
            valid_lines.append(line)
            continue
        try:
            # Check if line is a valid statement
            ast.parse(line_stripped)
            valid_lines.append(line)
        except SyntaxError:
            # Try as expression
            try:
                ast.parse(f"({line_stripped})")
                valid_lines.append(line)
            except:
                pass
    
    if valid_lines:
        try:
            reconstructed = '\n'.join(valid_lines)
            ast.parse(reconstructed)
            if len(reconstructed.strip()) > 20:
                return reconstructed
        except SyntaxError:
            pass
    
    # Strategy 8: Look for function definitions and extract them
    func_match = re.search(r'(def\s+\w+\s*\([^)]*\)\s*:.*?)(?=\ndef\s|\nclass\s|\Z)', code, re.DOTALL)
    if func_match:
        try:
            func_code = func_match.group(1).strip()
            # Ensure function body
            if not re.search(r':\s*\n\s+\S', func_code):
                func_code += '\n    pass'
            ast.parse(func_code)
            return func_code
        except SyntaxError:
            pass
    
    # Strategy 9: Try fixing common indent issues
    try:
        # Remove all leading indentation and re-add consistently
        lines = code.split('\n')
        min_indent = float('inf')
        for line in lines:
            stripped = line.lstrip()
            if stripped:
                indent = len(line) - len(stripped)
                min_indent = min(min_indent, indent)
        
        if min_indent > 0 and min_indent != float('inf'):
            fixed_lines = []
            for line in lines:
                if line.strip():
                    fixed_lines.append(line[min_indent:] if len(line) >= min_indent else line)
                else:
                    fixed_lines.append('')
            fixed = '\n'.join(fixed_lines)
            ast.parse(fixed)
            return fixed
    except SyntaxError:
        pass
    
    return None


def _balance_brackets(code: str) -> str:
    """Balance unclosed brackets by adding closing ones at the end."""
    stack = []
    bracket_pairs = {'(': ')', '[': ']', '{': '}'}
    
    for char in code:
        if char in bracket_pairs:
            stack.append(bracket_pairs[char])
        elif char in bracket_pairs.values():
            if stack and stack[-1] == char:
                stack.pop()
    
    # Add missing closing brackets
    return code + ''.join(reversed(stack))


def ast_to_graph(
    ast_tree: ast.AST, max_nodes: int = 100
) -> Tuple[nx.DiGraph, Dict[int, List[float]]]:
    """
    Converts a Python Abstract Syntax Tree (AST) into a NetworkX directed graph
    with enhanced semantic features.

    Each node in the AST becomes a node in the graph, and edges represent
    parent-child relationships. Node features include:
    
    Feature vector (16 dimensions):
    [0]  AST node type ID (0-49)
    [1]  Function name hash (0-1, for Call nodes)
    [2]  Is dangerous function (0 or 1)
    [3]  Danger category (0-7)
    [4]  Is user input source (0 or 1)
    [5]  Has string concatenation (0 or 1)
    [6]  Is SQL-related (0 or 1)
    [7]  Is deserialization (0 or 1)
    [8]  Is file operation (0 or 1)
    [9]  Is crypto operation (0 or 1)
    [10] Is network operation (0 or 1)
    [11] Module name hash (0-1)
    [12] Is in dangerous import context (0 or 1)
    [13] Depth in AST (normalized)
    [14] Has dangerous child (0 or 1) - filled in second pass
    [15] Parent is dangerous (0 or 1)

    Args:
        ast_tree: The root of the AST to convert.
        max_nodes: The maximum number of nodes to include in the graph.

    Returns:
        A tuple containing:
        - The NetworkX DiGraph.
        - A dictionary mapping node IDs to their feature vectors.
    """
    graph = nx.DiGraph()
    node_id_counter = 0
    node_features: Dict[int, List[float]] = {}
    
    # Track imported dangerous modules
    dangerous_imports: Set[str] = set()
    
    # First pass: identify dangerous imports
    for node in ast.walk(ast_tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in DANGEROUS_DESERIALIZE_MODULES or \
                   alias.name in {'os', 'subprocess', 'commands'}:
                    dangerous_imports.add(alias.asname or alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module in DANGEROUS_DESERIALIZE_MODULES or \
               node.module in {'os', 'subprocess', 'commands'}:
                for alias in node.names:
                    dangerous_imports.add(alias.asname or alias.name)
    
    # Track parent danger state
    parent_danger_stack = [False]
    
    def traverse(node: ast.AST, parent_id: int = None, depth: int = 0):
        nonlocal node_id_counter
        if node_id_counter >= max_nodes:
            return

        current_id = node_id_counter
        node_id_counter += 1

        # Initialize feature vector (16 dimensions)
        features = [0.0] * 16
        
        # [0] AST node type
        node_type = type(node).__name__
        node_type_id = NODE_TYPES.get(node_type, UNKNOWN_NODE_TYPE)
        features[0] = float(node_type_id)
        
        # [13] Depth (normalized, assuming max depth ~20)
        features[13] = min(depth / 20.0, 1.0)
        
        # [15] Parent is dangerous
        features[15] = 1.0 if parent_danger_stack[-1] else 0.0
        
        is_current_dangerous = False
        
        # Extract features based on node type
        if isinstance(node, ast.Call):
            func_name, full_path = _get_call_name(node)
            
            # [1] Function name hash
            features[1] = _hash_name(func_name)
            
            # [11] Module name hash
            module_name = full_path.rsplit('.', 1)[0] if '.' in full_path else ''
            features[11] = _hash_name(module_name)
            
            # Check if dangerous
            is_dangerous, danger_cat = _is_dangerous_call(func_name, full_path)
            
            # [2] Is dangerous function
            features[2] = 1.0 if is_dangerous else 0.0
            is_current_dangerous = is_dangerous
            
            # [3] Danger category
            features[3] = float(danger_cat) / 7.0  # Normalize to 0-1
            
            # Specific danger type flags
            # [6] SQL-related
            features[6] = 1.0 if danger_cat == 3 else 0.0
            # [7] Deserialization
            features[7] = 1.0 if danger_cat == 2 else 0.0
            # [8] File operation
            features[8] = 1.0 if danger_cat == 5 else 0.0
            # [9] Crypto operation
            features[9] = 1.0 if danger_cat == 4 else 0.0
            # [10] Network operation
            features[10] = 1.0 if danger_cat == 6 else 0.0
            
            # [12] In dangerous import context
            if module_name in dangerous_imports or func_name in dangerous_imports:
                features[12] = 1.0
                is_current_dangerous = True
        
        elif isinstance(node, ast.Name):
            # [1] Name hash
            features[1] = _hash_name(node.id)
            
            # [4] Is user input source
            if _is_user_input(node.id):
                features[4] = 1.0
            
            # [12] Is from dangerous import
            if node.id in dangerous_imports:
                features[12] = 1.0
        
        elif isinstance(node, ast.Attribute):
            # [1] Attribute name hash
            features[1] = _hash_name(node.attr)
            
            # [4] User input check
            if _is_user_input(node.attr):
                features[4] = 1.0
        
        elif isinstance(node, ast.BinOp):
            # [5] String concatenation
            if _has_string_concat(node):
                features[5] = 1.0
        
        elif isinstance(node, ast.JoinedStr):
            # f-string - potential for injection
            features[5] = 1.0
        
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            # Mark dangerous imports
            module = getattr(node, 'module', None)
            if module in DANGEROUS_DESERIALIZE_MODULES or \
               module in {'os', 'subprocess'}:
                features[12] = 1.0
                is_current_dangerous = True

        # Add edge from parent to current node
        if parent_id is not None:
            graph.add_edge(parent_id, current_id)

        node_features[current_id] = features
        
        # Track danger for children
        parent_danger_stack.append(is_current_dangerous or parent_danger_stack[-1])
        
        # Recursively traverse children
        for child in ast.iter_child_nodes(node):
            traverse(child, current_id, depth + 1)
        
        parent_danger_stack.pop()

    traverse(ast_tree)
    
    # Second pass: propagate "has dangerous child" upward
    # Build reverse mapping
    for parent_id, child_id in graph.edges():
        if parent_id in node_features and child_id in node_features:
            if node_features[child_id][2] > 0:  # Child is dangerous
                node_features[parent_id][14] = 1.0
    
    return graph, node_features


def code_to_pyg_graph(
    code: str, label: int, max_nodes: int = 100, num_node_features: int = 16
) -> Data | None:
    """
    Converts a string of Python code into a PyTorch Geometric Data object
    with enhanced semantic features.

    This function orchestrates parsing the code into an AST, converting the AST
    to a graph with rich semantic features, and then transforming it into a 
    PyG-compatible format.
    
    The enhanced features include:
    - AST node type
    - Function/attribute name hashes
    - Dangerous function detection (exec, eval, os.system, etc.)
    - Deserialization risk (pickle, yaml, etc.)
    - SQL injection indicators
    - Weak cryptography detection
    - User input source detection
    - String concatenation patterns
    
    For incomplete code snippets (common in security advisories), it will
    attempt to fix them before parsing.

    Args:
        code: The Python code snippet.
        label: The integer label (e.g., 0 for safe, 1 for vulnerable).
        max_nodes: The maximum number of nodes for the graph.
        num_node_features: The fixed size of the feature vector (default 16).

    Returns:
        A PyTorch Geometric `Data` object, or `None` if parsing or
        graph construction fails.
    """
    try:
        # First try to parse as-is
        try:
            ast_tree = ast.parse(code)
        except SyntaxError:
            # Try to fix incomplete code
            fixed_code = fix_incomplete_code(code)
            if fixed_code is None:
                return None
            ast_tree = ast.parse(fixed_code)
        
        graph, node_features_dict = ast_to_graph(ast_tree, max_nodes=max_nodes)

        if not graph.nodes:
            return None

        # Features are now already 16 dimensions from ast_to_graph
        # Just ensure correct size (pad or truncate if needed)
        padded_features = []
        for i in sorted(node_features_dict.keys()):
            feature_vec = node_features_dict[i]
            # Ensure exact size
            if len(feature_vec) < num_node_features:
                feature_vec = feature_vec + [0.0] * (num_node_features - len(feature_vec))
            padded_features.append(feature_vec[:num_node_features])

        # Convert to PyTorch Geometric format
        pyg_graph = from_networkx(graph)
        pyg_graph.x = torch.tensor(padded_features, dtype=torch.float)
        pyg_graph.y = torch.tensor([label], dtype=torch.long)

        return pyg_graph

    except (SyntaxError, ValueError, RecursionError):
        # Ignore code that fails to parse even after fixing
        return None
