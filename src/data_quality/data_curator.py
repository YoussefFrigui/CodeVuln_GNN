"""
Enhanced Data Curator for High-Quality Vulnerability Dataset

This module provides tools for collecting, curating, and validating diverse,
high-quality vulnerability data from multiple sources.

Features:
- Multi-source data collection (CVE, GitHub, synthetic)
- Quality filtering (completeness, syntactic validity, context)
- Diversity maximization (CWE types, code patterns, complexity)
- Hard negative mining (similar safe code)
- Data validation and deduplication
"""

import ast
import json
import hashlib
import re
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass, asdict
from collections import defaultdict
import requests
from pathlib import Path


@dataclass
class VulnerabilityExample:
    """Structured vulnerability example with metadata."""
    id: str
    source: str  # 'cve', 'github_advisory', 'synthetic', 'nvd'
    cwe_id: Optional[str]
    severity: str
    vulnerable_code: str
    fixed_code: Optional[str]
    description: str
    language: str = "python"
    complexity: Optional[int] = None  # Cyclomatic complexity
    loc: Optional[int] = None  # Lines of code
    has_context: bool = False  # Has surrounding function context
    quality_score: float = 0.0
    metadata: Dict = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}
        self.loc = len(self.vulnerable_code.split('\n'))
        self.quality_score = self._calculate_quality()
    
    def _calculate_quality(self) -> float:
        """Calculate quality score based on multiple factors."""
        score = 0.0
        
        # Has fix (before/after pairs are more valuable)
        if self.fixed_code and len(self.fixed_code) > 10:
            score += 0.3
        
        # Has CWE classification
        if self.cwe_id:
            score += 0.2
        
        # Has full function context
        if self.has_context:
            score += 0.2
        
        # Code is syntactically valid
        try:
            ast.parse(self.vulnerable_code)
            score += 0.2
        except:
            score -= 0.3
        
        # Has meaningful description
        if self.description and len(self.description) > 50:
            score += 0.1
        
        return max(0.0, min(1.0, score))
    
    def get_code_hash(self) -> str:
        """Get hash for deduplication."""
        # Normalize code (remove comments, whitespace)
        normalized = re.sub(r'#.*', '', self.vulnerable_code)
        normalized = re.sub(r'\s+', ' ', normalized).strip()
        return hashlib.md5(normalized.encode()).hexdigest()


class DataCurator:
    """Curate high-quality diverse vulnerability dataset."""
    
    def __init__(self, config: Dict):
        self.config = config
        self.examples: List[VulnerabilityExample] = []
        self.seen_hashes: Set[str] = set()
        self.cwe_distribution: Dict[str, int] = defaultdict(int)
        
    def add_example(self, example: VulnerabilityExample) -> bool:
        """
        Add example if it passes quality checks and isn't duplicate.
        
        Returns:
            True if added, False if rejected/duplicate
        """
        # Check for duplicates
        code_hash = example.get_code_hash()
        if code_hash in self.seen_hashes:
            return False
        
        # Quality threshold
        min_quality = self.config.get('min_quality_score', 0.3)
        if example.quality_score < min_quality:
            return False
        
        # Must have some code
        if len(example.vulnerable_code.strip()) < 20:
            return False
        
        self.examples.append(example)
        self.seen_hashes.add(code_hash)
        if example.cwe_id:
            self.cwe_distribution[example.cwe_id] += 1
        
        return True
    
    def collect_from_nvd(self, api_key: Optional[str] = None, 
                         max_results: int = 1000) -> int:
        """
        Collect vulnerabilities from National Vulnerability Database (NVD).
        
        Args:
            api_key: NVD API key (optional, increases rate limit)
            max_results: Maximum CVEs to fetch
            
        Returns:
            Number of examples added
        """
        print("🔍 Collecting from NVD (National Vulnerability Database)...")
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
        headers = {}
        if api_key:
            headers['apiKey'] = api_key
        
        added = 0
        start_index = 0
        results_per_page = 100
        
        while added < max_results:
            params = {
                'keywordSearch': 'python',
                'resultsPerPage': results_per_page,
                'startIndex': start_index
            }
            
            try:
                response = requests.get(base_url, params=params, headers=headers, timeout=30)
                response.raise_for_status()
                data = response.json()
                
                if 'vulnerabilities' not in data:
                    break
                
                for vuln_data in data['vulnerabilities']:
                    cve = vuln_data.get('cve', {})
                    cve_id = cve.get('id', 'unknown')
                    
                    # Extract CWE
                    cwe_id = None
                    weaknesses = cve.get('weaknesses', [])
                    if weaknesses:
                        cwe_data = weaknesses[0].get('description', [])
                        if cwe_data:
                            cwe_id = cwe_data[0].get('value')
                    
                    # Get description
                    descriptions = cve.get('descriptions', [])
                    description = descriptions[0].get('value', '') if descriptions else ''
                    
                    # Get severity
                    metrics = cve.get('metrics', {})
                    severity = 'MEDIUM'
                    if 'cvssMetricV31' in metrics:
                        severity = metrics['cvssMetricV31'][0].get('cvssData', {}).get('baseSeverity', 'MEDIUM')
                    
                    # Extract references for potential code
                    references = cve.get('references', [])
                    github_refs = [ref.get('url') for ref in references 
                                  if 'github.com' in ref.get('url', '')]
                    
                    # Try to fetch code from GitHub references
                    for ref_url in github_refs[:2]:  # Check first 2 GitHub refs
                        code = self._fetch_code_from_github_ref(ref_url)
                        if code:
                            example = VulnerabilityExample(
                                id=cve_id,
                                source='nvd',
                                cwe_id=cwe_id,
                                severity=severity,
                                vulnerable_code=code,
                                fixed_code=None,
                                description=description,
                                has_context=True,
                                metadata={'url': ref_url}
                            )
                            if self.add_example(example):
                                added += 1
                            break
                
                start_index += results_per_page
                
                # Respect rate limits
                if not api_key:
                    import time
                    time.sleep(6)  # 10 requests per minute without key
                else:
                    time.sleep(0.6)  # 50 requests per minute with key
                
                if len(data.get('vulnerabilities', [])) < results_per_page:
                    break
                    
            except Exception as e:
                print(f"Error fetching NVD data: {e}")
                break
        
        print(f"✓ Added {added} examples from NVD")
        return added
    
    def _fetch_code_from_github_ref(self, url: str) -> Optional[str]:
        """Try to extract code from GitHub reference URL."""
        # This is a simplified version - you'd want more robust parsing
        if '/commit/' in url:
            # Extract code from commit diff
            parts = url.split('/commit/')
            if len(parts) == 2:
                repo_url = parts[0].replace('https://github.com/', '')
                commit_sha = parts[1].split('#')[0].split('?')[0]
                
                api_url = f"https://api.github.com/repos/{repo_url}/commits/{commit_sha}"
                try:
                    response = requests.get(api_url, timeout=10)
                    if response.status_code == 200:
                        commit_data = response.json()
                        files = commit_data.get('files', [])
                        
                        for file in files:
                            if file.get('filename', '').endswith('.py'):
                                patch = file.get('patch', '')
                                # Extract removed lines (vulnerable code)
                                vulnerable_lines = []
                                for line in patch.split('\n'):
                                    if line.startswith('-') and not line.startswith('---'):
                                        vulnerable_lines.append(line[1:])
                                
                                if vulnerable_lines:
                                    return '\n'.join(vulnerable_lines)
                except:
                    pass
        return None
    
    def generate_synthetic_vulnerabilities(self, count: int = 100) -> int:
        """
        Generate synthetic vulnerabilities based on common CWE patterns.
        
        This creates controlled, valid Python code with known vulnerabilities.
        """
        print(f"🔬 Generating {count} synthetic vulnerabilities...")
        
        templates = {
            'CWE-89': self._generate_sql_injection,
            'CWE-79': self._generate_xss,
            'CWE-78': self._generate_command_injection,
            'CWE-502': self._generate_unsafe_deserialization,
            'CWE-22': self._generate_path_traversal,
            'CWE-798': self._generate_hardcoded_credentials,
            'CWE-327': self._generate_weak_crypto,
            'CWE-918': self._generate_ssrf,
        }
        
        added = 0
        for cwe_id, generator_func in templates.items():
            # Generate multiple variations per CWE
            variations = count // len(templates)
            for i in range(variations):
                try:
                    vuln_code, fixed_code, description = generator_func(i)
                    
                    example = VulnerabilityExample(
                        id=f"synthetic_{cwe_id}_{i}",
                        source='synthetic',
                        cwe_id=cwe_id,
                        severity='HIGH',
                        vulnerable_code=vuln_code,
                        fixed_code=fixed_code,
                        description=description,
                        has_context=True,
                        metadata={'variation': i}
                    )
                    
                    if self.add_example(example):
                        added += 1
                except Exception as e:
                    print(f"Error generating {cwe_id}: {e}")
                    continue
        
        print(f"✓ Generated {added} synthetic examples")
        return added
    
    def _generate_sql_injection(self, variation: int) -> Tuple[str, str, str]:
        """Generate SQL injection vulnerability."""
        var_names = ['user_input', 'username', 'search_term', 'filter_value']
        table_names = ['users', 'products', 'orders', 'customers']
        
        var = var_names[variation % len(var_names)]
        table = table_names[variation % len(table_names)]
        
        vulnerable = f"""def search_{table}({var}):
    # Vulnerable: Direct string concatenation
    query = "SELECT * FROM {table} WHERE name = '" + {var} + "'"
    cursor.execute(query)
    return cursor.fetchall()"""
        
        fixed = f"""def search_{table}({var}):
    # Fixed: Use parameterized query
    query = "SELECT * FROM {table} WHERE name = %s"
    cursor.execute(query, ({var},))
    return cursor.fetchall()"""
        
        description = f"SQL Injection via unsanitized {var} in SELECT query"
        
        return vulnerable, fixed, description
    
    def _generate_xss(self, variation: int) -> Tuple[str, str, str]:
        """Generate Cross-Site Scripting vulnerability."""
        contexts = ['render_comment', 'display_message', 'show_profile', 'render_post']
        
        func_name = contexts[variation % len(contexts)]
        
        vulnerable = f"""def {func_name}(user_content):
    # Vulnerable: Unescaped user content
    html = f"<div>{{user_content}}</div>"
    return html"""
        
        fixed = f"""from html import escape

def {func_name}(user_content):
    # Fixed: Escape user content
    html = f"<div>{{escape(user_content)}}</div>"
    return html"""
        
        description = f"XSS vulnerability in {func_name} - unescaped user input"
        
        return vulnerable, fixed, description
    
    def _generate_command_injection(self, variation: int) -> Tuple[str, str, str]:
        """Generate command injection vulnerability."""
        commands = ['ping', 'nslookup', 'wget', 'curl']
        
        cmd = commands[variation % len(commands)]
        
        vulnerable = f"""import os

def check_host(hostname):
    # Vulnerable: Unsanitized input in shell command
    result = os.system(f"{cmd} {{hostname}}")
    return result"""
        
        fixed = f"""import subprocess
import shlex

def check_host(hostname):
    # Fixed: Use subprocess with argument list
    result = subprocess.run(["{cmd}", hostname], capture_output=True)
    return result.returncode"""
        
        description = f"Command injection via unsanitized hostname in {cmd}"
        
        return vulnerable, fixed, description
    
    def _generate_unsafe_deserialization(self, variation: int) -> Tuple[str, str, str]:
        """Generate unsafe deserialization vulnerability."""
        vulnerable = """import pickle

def load_user_data(data_file):
    # Vulnerable: Unpickling untrusted data
    with open(data_file, 'rb') as f:
        user_data = pickle.load(f)
    return user_data"""
        
        fixed = """import json

def load_user_data(data_file):
    # Fixed: Use safe serialization format
    with open(data_file, 'r') as f:
        user_data = json.load(f)
    return user_data"""
        
        description = "Unsafe deserialization using pickle on untrusted data"
        
        return vulnerable, fixed, description
    
    def _generate_path_traversal(self, variation: int) -> Tuple[str, str, str]:
        """Generate path traversal vulnerability."""
        vulnerable = """def read_user_file(filename):
    # Vulnerable: No path validation
    file_path = f"/uploads/{filename}"
    with open(file_path, 'r') as f:
        return f.read()"""
        
        fixed = """import os
from pathlib import Path

def read_user_file(filename):
    # Fixed: Validate path is within uploads directory
    base_dir = Path("/uploads").resolve()
    file_path = (base_dir / filename).resolve()
    
    if not str(file_path).startswith(str(base_dir)):
        raise ValueError("Invalid file path")
    
    with open(file_path, 'r') as f:
        return f.read()"""
        
        description = "Path traversal - unsanitized filename allows directory traversal"
        
        return vulnerable, fixed, description
    
    def _generate_hardcoded_credentials(self, variation: int) -> Tuple[str, str, str]:
        """Generate hardcoded credentials vulnerability."""
        services = ['database', 'api', 's3', 'redis']
        service = services[variation % len(services)]
        
        vulnerable = f"""def connect_to_{service}():
    # Vulnerable: Hardcoded credentials
    username = "admin"
    password = "password123"
    connection = connect(username, password)
    return connection"""
        
        fixed = f"""import os

def connect_to_{service}():
    # Fixed: Use environment variables
    username = os.environ.get('{service.upper()}_USER')
    password = os.environ.get('{service.upper()}_PASS')
    connection = connect(username, password)
    return connection"""
        
        description = f"Hardcoded credentials for {service} connection"
        
        return vulnerable, fixed, description
    
    def _generate_weak_crypto(self, variation: int) -> Tuple[str, str, str]:
        """Generate weak cryptography vulnerability."""
        vulnerable = """import hashlib

def hash_password(password):
    # Vulnerable: Using MD5 for passwords
    return hashlib.md5(password.encode()).hexdigest()"""
        
        fixed = """from argon2 import PasswordHasher

def hash_password(password):
    # Fixed: Use strong password hashing
    ph = PasswordHasher()
    return ph.hash(password)"""
        
        description = "Weak cryptography - using MD5 for password hashing"
        
        return vulnerable, fixed, description
    
    def _generate_ssrf(self, variation: int) -> Tuple[str, str, str]:
        """Generate Server-Side Request Forgery vulnerability."""
        vulnerable = """import requests

def fetch_external_data(url):
    # Vulnerable: Unvalidated URL from user
    response = requests.get(url)
    return response.text"""
        
        fixed = """import requests
from urllib.parse import urlparse

ALLOWED_DOMAINS = ['api.example.com', 'cdn.example.com']

def fetch_external_data(url):
    # Fixed: Validate URL domain
    parsed = urlparse(url)
    if parsed.netloc not in ALLOWED_DOMAINS:
        raise ValueError("URL not in allowed domains")
    
    response = requests.get(url, timeout=5)
    return response.text"""
        
        description = "SSRF vulnerability - unvalidated external URL requests"
        
        return vulnerable, fixed, description
    
    def mine_hard_negatives(self, safe_code_dir: str, count: int = 500) -> int:
        """
        Mine hard negative examples (safe code similar to vulnerabilities).
        
        Strategy: Find safe code that uses similar APIs/patterns but correctly.
        """
        print(f"⛏️  Mining {count} hard negative examples...")
        
        # Patterns that appear in vulnerabilities but can be safe
        patterns = {
            'sql_safe': ['execute.*%s', 'executemany', 'parameterized'],
            'command_safe': ['subprocess.run\([^)]*shell=False', 'shlex.quote'],
            'crypto_safe': ['hashlib.sha256', 'bcrypt', 'argon2'],
            'file_safe': ['Path.*resolve', 'os.path.abspath.*startswith'],
        }
        
        # This would scan your safe code corpus and find matching examples
        # For now, returning placeholder - implement based on your safe code source
        
        print(f"✓ Mined {0} hard negatives (implement based on your corpus)")
        return 0
    
    def get_statistics(self) -> Dict:
        """Get dataset statistics."""
        total = len(self.examples)
        
        sources = defaultdict(int)
        severities = defaultdict(int)
        quality_scores = []
        
        for ex in self.examples:
            sources[ex.source] += 1
            # Handle severity - ensure it's a string
            severity_key = str(ex.severity) if ex.severity else 'UNKNOWN'
            severities[severity_key] += 1
            quality_scores.append(ex.quality_score)
        
        return {
            'total_examples': total,
            'sources': dict(sources),
            'severities': dict(severities),
            'cwe_types': len(self.cwe_distribution),
            'cwe_distribution': dict(self.cwe_distribution),
            'avg_quality_score': sum(quality_scores) / len(quality_scores) if quality_scores else 0,
            'has_fixes': sum(1 for ex in self.examples if ex.fixed_code)
        }
    
    def export_dataset(self, output_path: str):
        """Export curated dataset to JSON."""
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        
        data = {
            'examples': [asdict(ex) for ex in self.examples],
            'statistics': self.get_statistics(),
            'metadata': {
                'version': '1.0',
                'curator': 'DataCurator',
                'config': self.config
            }
        }
        
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"\n📊 Dataset exported to: {output_path}")
        print(f"Total examples: {len(self.examples)}")
        
        stats = self.get_statistics()
        print(f"\nSources: {stats['sources']}")
        print(f"CWE types: {stats['cwe_types']}")
        print(f"Avg quality score: {stats['avg_quality_score']:.2f}")
        print(f"Examples with fixes: {stats['has_fixes']}")


def main():
    """Run data curation pipeline."""
    config = {
        'min_quality_score': 0.4,
        'output_dir': 'outputs/datasets/curated'
    }
    
    curator = DataCurator(config)
    
    # Collect from multiple sources
    # curator.collect_from_nvd(max_results=500)  # Uncomment with API key
    curator.generate_synthetic_vulnerabilities(count=200)
    
    # Export
    curator.export_dataset('outputs/datasets/curated_vulnerabilities.json')
    
    # Print CWE distribution
    stats = curator.get_statistics()
    print("\n📈 CWE Distribution:")
    for cwe, count in sorted(stats['cwe_distribution'].items(), 
                             key=lambda x: x[1], reverse=True)[:10]:
        print(f"  {cwe}: {count}")


if __name__ == '__main__':
    main()
