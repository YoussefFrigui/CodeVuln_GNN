"""
LLM-based Explainability Module for GNN Vulnerability Detection

This module provides human-readable explanations for vulnerability predictions
using Google's Gemini AI in a RAG-like architecture:
1. GNN Detection: Model predicts vulnerability score
2. Context Retrieval: Extract code patterns, AST info, dangerous functions
3. LLM Generation: Gemini explains the vulnerability in detail

Usage:
    from src.explainability.llm_explainer import VulnerabilityExplainer
    
    explainer = VulnerabilityExplainer(api_key="your-gemini-api-key")
    explanation = explainer.explain(code, gnn_result)
"""

import os
import ast
import re
from typing import Dict, List, Optional, Any
from dataclasses import dataclass


# Try to import google genai
try:
    from google import genai
    from google.genai import types
    GENAI_AVAILABLE = True
except ImportError:
    GENAI_AVAILABLE = False
    print("Warning: google-genai not installed. Run: pip install google-genai")


@dataclass
class VulnerabilityContext:
    """Context extracted from code for RAG-like retrieval."""
    code: str
    ast_summary: Dict[str, Any]
    dangerous_patterns: List[Dict[str, str]]
    function_calls: List[str]
    imports: List[str]
    string_operations: List[str]
    user_inputs: List[str]
    vulnerability_score: float
    is_vulnerable: bool


# Knowledge base of vulnerability patterns for context retrieval
VULNERABILITY_PATTERNS = {
    "sql_injection": {
        "patterns": [
            r"execute\s*\(",
            r"cursor\.execute",
            r"SELECT.*\+",
            r"SELECT.*%",
            r"SELECT.*\.format",
            r"INSERT.*\+",
            r"UPDATE.*\+",
            r"DELETE.*\+",
        ],
        "dangerous_functions": ["execute", "executemany", "raw", "cursor"],
        "cwe": "CWE-89",
        "description": "SQL Injection vulnerability - user input concatenated into SQL query",
    },
    "command_injection": {
        "patterns": [
            r"os\.system\s*\(",
            r"subprocess\.(call|run|Popen)",
            r"exec\s*\(",
            r"eval\s*\(",
            r"os\.popen",
            r"commands\.getoutput",
        ],
        "dangerous_functions": ["system", "popen", "exec", "eval", "call", "run", "Popen"],
        "cwe": "CWE-78",
        "description": "Command Injection - user input passed to shell commands",
    },
    "path_traversal": {
        "patterns": [
            r"open\s*\([^)]*\+",
            r"open\s*\([^)]*\.format",
            r"os\.path\.join.*\.\.",
            r"file\s*=.*\+",
        ],
        "dangerous_functions": ["open", "read", "write", "path.join"],
        "cwe": "CWE-22",
        "description": "Path Traversal - unsanitized user input in file paths",
    },
    "xss": {
        "patterns": [
            r"render_template_string",
            r"Markup\s*\(",
            r"\.html\s*\(",
            r"innerHTML",
            r"document\.write",
        ],
        "dangerous_functions": ["render_template_string", "Markup", "safe"],
        "cwe": "CWE-79",
        "description": "Cross-Site Scripting - user input rendered as HTML without escaping",
    },
    "deserialization": {
        "patterns": [
            r"pickle\.loads?",
            r"yaml\.load\s*\([^)]*\)",
            r"marshal\.loads?",
            r"shelve\.open",
        ],
        "dangerous_functions": ["loads", "load", "pickle", "yaml", "marshal"],
        "cwe": "CWE-502",
        "description": "Insecure Deserialization - untrusted data deserialized",
    },
    "hardcoded_credentials": {
        "patterns": [
            r"password\s*=\s*['\"]",
            r"secret\s*=\s*['\"]",
            r"api_key\s*=\s*['\"]",
            r"token\s*=\s*['\"]",
            r"AWS_SECRET",
        ],
        "dangerous_functions": [],
        "cwe": "CWE-798",
        "description": "Hardcoded Credentials - sensitive data embedded in source code",
    },
    "weak_crypto": {
        "patterns": [
            r"MD5\s*\(",
            r"SHA1\s*\(",
            r"DES\s*\(",
            r"hashlib\.md5",
            r"hashlib\.sha1",
        ],
        "dangerous_functions": ["md5", "sha1", "DES"],
        "cwe": "CWE-327",
        "description": "Weak Cryptography - use of broken or weak cryptographic algorithms",
    },
}


class CodeAnalyzer:
    """Analyzes code to extract context for LLM explanation."""
    
    @staticmethod
    def extract_ast_summary(code: str) -> Dict[str, Any]:
        """Extract AST summary for context."""
        try:
            tree = ast.parse(code)
            
            node_types = {}
            for node in ast.walk(tree):
                node_type = type(node).__name__
                node_types[node_type] = node_types.get(node_type, 0) + 1
            
            functions = []
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    functions.append({
                        "name": node.name,
                        "args": [arg.arg for arg in node.args.args],
                        "lineno": node.lineno,
                    })
            
            classes = [node.name for node in ast.walk(tree) 
                      if isinstance(node, ast.ClassDef)]
            
            return {
                "valid": True,
                "node_types": node_types,
                "total_nodes": sum(node_types.values()),
                "functions": functions,
                "classes": classes,
            }
        except SyntaxError as e:
            return {"valid": False, "error": str(e)}
    
    @staticmethod
    def extract_function_calls(code: str) -> List[str]:
        """Extract all function calls from code."""
        try:
            tree = ast.parse(code)
            calls = []
            
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        calls.append(node.func.id)
                    elif isinstance(node.func, ast.Attribute):
                        if isinstance(node.func.value, ast.Name):
                            calls.append(f"{node.func.value.id}.{node.func.attr}")
                        else:
                            calls.append(node.func.attr)
            
            return list(set(calls))
        except:
            return []
    
    @staticmethod
    def extract_imports(code: str) -> List[str]:
        """Extract all imports from code."""
        try:
            tree = ast.parse(code)
            imports = []
            
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append(alias.name)
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imports.append(node.module)
            
            return list(set(imports))
        except:
            return []
    
    @staticmethod
    def extract_string_operations(code: str) -> List[str]:
        """Find string concatenation and formatting operations."""
        operations = []
        
        # String concatenation with +
        if re.search(r'["\'].*\+|.*\+.*["\']', code):
            operations.append("string_concatenation")
        
        # f-strings
        if re.search(r'f["\']', code):
            operations.append("f_string")
        
        # .format()
        if ".format(" in code:
            operations.append("str_format")
        
        # % formatting
        if re.search(r'%\s*\(', code) or re.search(r'%s|%d', code):
            operations.append("percent_format")
        
        return operations
    
    @staticmethod
    def find_user_input_sources(code: str) -> List[str]:
        """Identify potential user input sources."""
        sources = []
        
        patterns = {
            "request.form": "Flask form data",
            "request.args": "Flask URL parameters",
            "request.get_json": "Flask JSON body",
            "input(": "User console input",
            "sys.argv": "Command line arguments",
            "environ": "Environment variables",
            "request.GET": "Django GET parameters",
            "request.POST": "Django POST data",
        }
        
        for pattern, description in patterns.items():
            if pattern in code:
                sources.append(description)
        
        return sources
    
    @staticmethod
    def detect_vulnerability_patterns(code: str) -> List[Dict[str, str]]:
        """Detect known vulnerability patterns in code."""
        detected = []
        
        for vuln_type, info in VULNERABILITY_PATTERNS.items():
            for pattern in info["patterns"]:
                if re.search(pattern, code, re.IGNORECASE):
                    detected.append({
                        "type": vuln_type,
                        "cwe": info["cwe"],
                        "description": info["description"],
                        "matched_pattern": pattern,
                    })
                    break  # One match per vulnerability type is enough
        
        return detected


class VulnerabilityExplainer:
    """
    LLM-based explainer for GNN vulnerability predictions.
    
    Uses a RAG-like architecture:
    1. Retrieve relevant context from code analysis
    2. Augment prompt with vulnerability patterns and AST info
    3. Generate explanation using Gemini
    """
    
    def __init__(self, api_key: Optional[str] = None, model: str = "gemini-2.5-pro"):
        """
        Initialize the explainer.
        
        Args:
            api_key: Google Gemini API key. If None, uses GEMINI_API_KEY env var.
            model: Gemini model to use (default: gemini-2.0-flash)
        """
        self.model = model
        self.analyzer = CodeAnalyzer()
        
        if not GENAI_AVAILABLE:
            self.client = None
            print("⚠️ Google GenAI not available. Install with: pip install google-genai")
            return
        
        # Get API key from parameter or environment
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        
        if self.api_key:
            self.client = genai.Client(api_key=self.api_key)
        else:
            self.client = None
            print("⚠️ No Gemini API key provided. Set GEMINI_API_KEY environment variable.")
    
    def _build_context(self, code: str, gnn_result: Dict[str, Any]) -> VulnerabilityContext:
        """Build context for RAG-like retrieval."""
        return VulnerabilityContext(
            code=code,
            ast_summary=self.analyzer.extract_ast_summary(code),
            dangerous_patterns=self.analyzer.detect_vulnerability_patterns(code),
            function_calls=self.analyzer.extract_function_calls(code),
            imports=self.analyzer.extract_imports(code),
            string_operations=self.analyzer.extract_string_operations(code),
            user_inputs=self.analyzer.find_user_input_sources(code),
            vulnerability_score=gnn_result.get("vulnerability_score", 0),
            is_vulnerable=gnn_result.get("is_vulnerable", False),
        )
    
    def _build_prompt(self, context: VulnerabilityContext) -> str:
        """Build the prompt for Gemini with retrieved context."""
        
        # Determine vulnerability status
        if context.is_vulnerable:
            status = f"🔴 VULNERABLE (confidence: {context.vulnerability_score:.1%})"
        else:
            status = f"🟢 SAFE (confidence: {1 - context.vulnerability_score:.1%})"
        
        # Build pattern information
        pattern_info = ""
        if context.dangerous_patterns:
            pattern_info = "\n**Detected Vulnerability Patterns:**\n"
            for p in context.dangerous_patterns:
                pattern_info += f"- {p['type'].replace('_', ' ').title()} ({p['cwe']}): {p['description']}\n"
        
        # Build function call info
        dangerous_calls = []
        for call in context.function_calls:
            for vuln_type, info in VULNERABILITY_PATTERNS.items():
                if any(dc in call.lower() for dc in info["dangerous_functions"]):
                    dangerous_calls.append(f"{call} (potentially dangerous)")
                    break
        
        calls_info = ""
        if dangerous_calls:
            calls_info = f"\n**Potentially Dangerous Function Calls:**\n- " + "\n- ".join(dangerous_calls)
        
        # Build user input info
        input_info = ""
        if context.user_inputs:
            input_info = f"\n**User Input Sources Detected:**\n- " + "\n- ".join(context.user_inputs)
        
        # Build string operation info
        string_info = ""
        if context.string_operations:
            string_info = f"\n**String Operations (potential injection vectors):**\n- " + "\n- ".join(context.string_operations)
        
        prompt = f"""You are a cybersecurity expert analyzing Python code for security vulnerabilities.

## GNN Model Prediction
{status}

## Code Under Analysis
```python
{context.code}
```

## Extracted Context
**Imports:** {', '.join(context.imports) if context.imports else 'None detected'}
**Function Calls:** {', '.join(context.function_calls[:10]) if context.function_calls else 'None detected'}
{pattern_info}{calls_info}{input_info}{string_info}

## Your Task
Based on the GNN model's prediction and the extracted context, provide:

1. **Summary**: A brief 1-2 sentence summary of whether this code is vulnerable and why.

2. **Detailed Analysis**: Explain the specific security issue(s) found, including:
   - What vulnerability type(s) are present (if any)
   - Which line(s) of code are problematic
   - How an attacker could exploit this vulnerability

3. **Risk Level**: Rate as Critical/High/Medium/Low/None with justification.

4. **Remediation**: Provide specific code fixes or best practices to address the vulnerability.

Be concise but thorough. If the code is safe, explain why the patterns detected (if any) are not exploitable in this context.
"""
        return prompt
    
    def explain(self, code: str, gnn_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate an explanation for the GNN's vulnerability prediction.
        
        Args:
            code: The Python code that was analyzed
            gnn_result: Dictionary containing GNN results with keys:
                - is_vulnerable: bool
                - vulnerability_score: float (0-1)
                - confidence: float
        
        Returns:
            Dictionary with:
                - explanation: str (LLM-generated explanation)
                - context: dict (extracted code context)
                - success: bool
                - error: str (if any)
        """
        # Build context (RAG retrieval step)
        context = self._build_context(code, gnn_result)
        
        # If no API client, return context-only analysis
        if self.client is None:
            return {
                "success": False,
                "error": "Gemini API not configured. Set GEMINI_API_KEY environment variable.",
                "context": {
                    "dangerous_patterns": context.dangerous_patterns,
                    "function_calls": context.function_calls,
                    "imports": context.imports,
                    "user_inputs": context.user_inputs,
                    "string_operations": context.string_operations,
                },
                "fallback_explanation": self._generate_fallback_explanation(context),
            }
        
        # Build prompt with context (RAG augmentation step)
        prompt = self._build_prompt(context)
        
        try:
            # Generate explanation (RAG generation step)
            response = self.client.models.generate_content(
                model=self.model,
                contents=prompt,
                config=types.GenerateContentConfig(
                    temperature=0.3,  # Lower temperature for more focused output
                    max_output_tokens=8192,  # Maximum output for comprehensive explanations
                )
            )
            
            return {
                "success": True,
                "explanation": response.text,
                "context": {
                    "dangerous_patterns": context.dangerous_patterns,
                    "function_calls": context.function_calls,
                    "imports": context.imports,
                    "user_inputs": context.user_inputs,
                    "string_operations": context.string_operations,
                    "vulnerability_score": context.vulnerability_score,
                },
            }
        
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "context": {
                    "dangerous_patterns": context.dangerous_patterns,
                    "function_calls": context.function_calls,
                },
                "fallback_explanation": self._generate_fallback_explanation(context),
            }
    
    def _generate_fallback_explanation(self, context: VulnerabilityContext) -> str:
        """Generate a basic explanation without LLM when API is unavailable."""
        if not context.is_vulnerable:
            return "✅ **Safe Code**: The GNN model did not detect vulnerability patterns in this code."
        
        explanation = f"⚠️ **Potentially Vulnerable Code** (Score: {context.vulnerability_score:.1%})\n\n"
        
        if context.dangerous_patterns:
            explanation += "**Detected Issues:**\n"
            for p in context.dangerous_patterns:
                explanation += f"- **{p['type'].replace('_', ' ').title()}** ({p['cwe']}): {p['description']}\n"
        
        if context.user_inputs:
            explanation += f"\n**User Input Sources:** {', '.join(context.user_inputs)}\n"
        
        if context.string_operations:
            explanation += f"\n**String Operations:** {', '.join(context.string_operations)} (potential injection vectors)\n"
        
        explanation += "\n*Note: For detailed analysis, configure the Gemini API key.*"
        
        return explanation
    
    def explain_batch(self, code_samples: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Explain multiple code samples.
        
        Args:
            code_samples: List of dicts with 'code' and 'gnn_result' keys
        
        Returns:
            List of explanation results
        """
        results = []
        for sample in code_samples:
            result = self.explain(sample["code"], sample["gnn_result"])
            results.append(result)
        return results


# Convenience function for quick explanations
def explain_vulnerability(
    code: str,
    is_vulnerable: bool,
    vulnerability_score: float,
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Quick function to explain a vulnerability prediction.
    
    Args:
        code: Python code to analyze
        is_vulnerable: GNN prediction (True/False)
        vulnerability_score: GNN vulnerability probability (0-1)
        api_key: Optional Gemini API key
    
    Returns:
        Explanation dictionary
    """
    explainer = VulnerabilityExplainer(api_key=api_key)
    return explainer.explain(
        code=code,
        gnn_result={
            "is_vulnerable": is_vulnerable,
            "vulnerability_score": vulnerability_score,
        }
    )


if __name__ == "__main__":
    # Test the explainer
    test_code = '''
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    return cursor.fetchone()
'''
    
    print("Testing VulnerabilityExplainer...")
    print("=" * 50)
    
    explainer = VulnerabilityExplainer()
    result = explainer.explain(
        code=test_code,
        gnn_result={
            "is_vulnerable": True,
            "vulnerability_score": 0.85,
        }
    )
    
    if result["success"]:
        print("\n📝 LLM Explanation:")
        print(result["explanation"])
    else:
        print(f"\n⚠️ Error: {result.get('error', 'Unknown')}")
        print("\n📝 Fallback Explanation:")
        print(result.get("fallback_explanation", ""))
    
    print("\n📊 Extracted Context:")
    for key, value in result.get("context", {}).items():
        print(f"  {key}: {value}")
