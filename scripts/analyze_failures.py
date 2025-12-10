"""Analyze why code snippets fail to parse."""
import json
import ast
import sys
import re
from collections import Counter
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from data_processing.graph_utils import fix_incomplete_code


# Vulnerability patterns to detect in code
VULN_PATTERNS = {
    'sql_injection': [r'execute\s*\(', r'cursor\.\w+\(', r'SELECT.*\+', r'INSERT.*\+', r'\.format\('],
    'command_injection': [r'os\.system', r'subprocess\.', r'Popen', r'shell=True'],
    'xss': [r'render_template_string', r'Markup\(', r'innerHTML', r'\|safe'],
    'path_traversal': [r'open\s*\(.*\+', r'os\.path\.join.*\+', r'file.*=.*\+'],
    'deserialization': [r'pickle\.load', r'yaml\.load', r'marshal\.load'],
    'crypto': [r'md5', r'sha1', r'DES', r'ECB'],
    'hardcoded_secret': [r'password\s*=\s*["\']', r'secret\s*=\s*["\']', r'api_key\s*=\s*["\']'],
}


def detect_vuln_type(code):
    """Detect vulnerability type from code patterns."""
    code_lower = code.lower()
    detected = []
    for vuln_type, patterns in VULN_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, code, re.IGNORECASE):
                detected.append(vuln_type)
                break
    return detected if detected else ['other']


def analyze_failures():
    # Load advisories
    adv = json.load(open('outputs/datasets/processed_advisories_with_code.json'))
    
    raw_fails = []
    raw_success = 0
    fixed_fails = []
    fixed_success = 0
    failed_with_metadata = []
    
    for a in adv:
        code = a.get('vulnerable_code', '')
        if not code or len(code.strip()) < 10:
            continue
            
        # Test raw parsing
        try:
            ast.parse(code)
            raw_success += 1
        except SyntaxError as e:
            raw_fails.append({
                'error': str(e.msg) if e.msg else 'Unknown',
                'code_preview': code[:150].replace('\n', '\\n')
            })
        
        # Test after fixing
        fixed = fix_incomplete_code(code)
        if fixed:
            fixed_success += 1
        else:
            vuln_types = detect_vuln_type(code)
            fixed_fails.append({
                'error': 'Fix failed',
                'code_preview': code[:150].replace('\n', '\\n'),
                'vuln_types': vuln_types,
                'severity': a.get('severity', 'Unknown'),
                'cwe': a.get('cwe_id', 'Unknown'),
            })
    
    total = raw_success + len(raw_fails)
    
    print("=" * 60)
    print("CODE PARSING ANALYSIS")
    print("=" * 60)
    print(f"\nTotal code snippets analyzed: {total}")
    print(f"\n📊 RAW PARSING (before fix):")
    print(f"   Success: {raw_success} ({raw_success/total*100:.1f}%)")
    print(f"   Failed:  {len(raw_fails)} ({len(raw_fails)/total*100:.1f}%)")
    
    print(f"\n📊 AFTER fix_incomplete_code():")
    print(f"   Success: {fixed_success} ({fixed_success/total*100:.1f}%)")
    print(f"   Failed:  {len(fixed_fails)} ({len(fixed_fails)/total*100:.1f}%)")
    
    print(f"\n📈 Improvement: +{fixed_success - raw_success} examples recovered")
    
    # Analyze error types
    print("\n" + "=" * 60)
    print("TOP ERROR TYPES (Raw parsing)")
    print("=" * 60)
    errors = Counter([f['error'] for f in raw_fails])
    for error, count in errors.most_common(15):
        print(f"   {count:4d} - {error}")
    
    # Analyze vulnerability types in failures
    print("\n" + "=" * 60)
    print("VULNERABILITY TYPES IN FAILED EXAMPLES")
    print("=" * 60)
    vuln_counts = Counter()
    for fail in fixed_fails:
        for vt in fail['vuln_types']:
            vuln_counts[vt] += 1
    
    for vuln_type, count in vuln_counts.most_common():
        print(f"   {count:4d} - {vuln_type}")
    
    # Severity distribution
    print("\n" + "=" * 60)
    print("SEVERITY OF FAILED EXAMPLES")
    print("=" * 60)
    # Handle case where severity might be a list
    severities = []
    for f in fixed_fails:
        sev = f.get('severity', 'unknown')
        if isinstance(sev, list):
            sev = sev[0] if sev else 'unknown'
        severities.append(str(sev) if sev else 'unknown')
    severity_counts = Counter(severities)
    for sev, count in severity_counts.most_common():
        print(f"   {count:4d} - {sev}")
    
    # Show examples of remaining failures by type
    print("\n" + "=" * 60)
    print("EXAMPLES OF FAILED SQL INJECTION CODE")
    print("=" * 60)
    sql_fails = [f for f in fixed_fails if 'sql_injection' in f['vuln_types']][:3]
    for i, fail in enumerate(sql_fails):
        print(f"\n--- Example {i+1} ---")
        print(f"Preview: {fail['code_preview'][:150]}...")


if __name__ == "__main__":
    analyze_failures()
