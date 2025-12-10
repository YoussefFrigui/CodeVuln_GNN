"""
Extract Vulnerable Code from Advisory Descriptions

Some advisories don't have commit URLs but contain code examples in their
description/details field. This script extracts those code snippets.

This adds ~52 additional vulnerable examples to the dataset.
"""

import json
import os
import re
from typing import List, Dict, Any, Optional
from tqdm import tqdm


def extract_code_from_description(text: str) -> List[str]:
    """
    Extract code blocks from advisory description text.
    
    Looks for:
    - Markdown code blocks: ```python ... ``` or ``` ... ```
    - Indented code blocks (4+ spaces)
    - Inline code that looks like Python
    
    Args:
        text: The advisory description/details text
        
    Returns:
        List of extracted code snippets
    """
    code_snippets = []
    
    if not text:
        return code_snippets
    
    # Pattern 1: Markdown code blocks with language specifier
    # ```python\ncode\n``` or ```py\ncode\n```
    pattern_md_lang = r'```(?:python|py)?\s*\n(.*?)```'
    matches = re.findall(pattern_md_lang, text, re.DOTALL | re.IGNORECASE)
    for match in matches:
        code = match.strip()
        if len(code) > 20 and looks_like_python(code):
            code_snippets.append(code)
    
    # Pattern 2: Generic markdown code blocks
    pattern_md = r'```\s*\n(.*?)```'
    matches = re.findall(pattern_md, text, re.DOTALL)
    for match in matches:
        code = match.strip()
        if len(code) > 20 and looks_like_python(code):
            if code not in code_snippets:  # Avoid duplicates
                code_snippets.append(code)
    
    # Pattern 3: Indented code blocks (4+ spaces at start of lines)
    lines = text.split('\n')
    current_block = []
    in_code_block = False
    
    for line in lines:
        if line.startswith('    ') or line.startswith('\t'):
            current_block.append(line)
            in_code_block = True
        else:
            if in_code_block and current_block:
                code = '\n'.join(current_block).strip()
                if len(code) > 20 and looks_like_python(code):
                    if code not in code_snippets:
                        code_snippets.append(code)
                current_block = []
            in_code_block = False
    
    # Don't forget last block
    if current_block:
        code = '\n'.join(current_block).strip()
        if len(code) > 20 and looks_like_python(code):
            if code not in code_snippets:
                code_snippets.append(code)
    
    return code_snippets


def looks_like_python(code: str) -> bool:
    """
    Check if a code snippet looks like Python code.
    """
    python_indicators = [
        'def ', 'class ', 'import ', 'from ', 'if ', 'for ', 'while ',
        'return ', 'print(', 'self.', '= ', '== ', 'None', 'True', 'False',
        'try:', 'except:', 'with ', 'as ', 'lambda ', 'yield ', 'async ',
        '__init__', '.py', 'raise ', 'assert '
    ]
    
    # Must have at least 2 Python indicators
    count = sum(1 for indicator in python_indicators if indicator in code)
    return count >= 2


def has_commit_url(advisory: Dict[str, Any]) -> bool:
    """Check if advisory has a GitHub commit or PR URL."""
    for ref in advisory.get('references', []):
        url = ref.get('url', '')
        if re.search(r'github\.com/.+/.+/(commit|pull)/\w+', url):
            return True
    return False


def extract_from_advisories(advisories_path: str) -> List[Dict[str, Any]]:
    """
    Extract code from advisories that have code in descriptions but no commit URLs.
    
    Args:
        advisories_path: Path to python_advisories.json
        
    Returns:
        List of extracted vulnerable code examples
    """
    print(f"Loading advisories from {advisories_path}...")
    with open(advisories_path, 'r', encoding='utf-8') as f:
        advisories = json.load(f)
    
    print(f"Loaded {len(advisories)} advisories")
    
    # Filter to those without commit URLs
    no_commit_advisories = [a for a in advisories if not has_commit_url(a)]
    print(f"Advisories without commit URLs: {len(no_commit_advisories)}")
    
    extracted_examples = []
    
    for advisory in tqdm(no_commit_advisories, desc="Extracting code from descriptions"):
        # Get description/details text
        description = advisory.get('details', '') or advisory.get('description', '') or ''
        summary = advisory.get('summary', '')
        
        # Try to extract code
        code_snippets = extract_code_from_description(description)
        
        if not code_snippets:
            # Also try summary
            code_snippets = extract_code_from_description(summary)
        
        # Get CWE IDs
        cwe_ids = advisory.get('database_specific', {}).get('cwe_ids', [])
        cwe_id = cwe_ids[0] if cwe_ids else ''
        
        # Get severity
        severity = advisory.get('severity', 'UNKNOWN')
        if isinstance(severity, list):
            severity = severity[0].get('type', 'UNKNOWN') if severity else 'UNKNOWN'
        
        for code in code_snippets:
            extracted_examples.append({
                'advisory_id': advisory.get('id', ''),
                'summary': advisory.get('summary', ''),
                'severity': severity,
                'cwe_id': cwe_id,
                'cwe_ids': cwe_ids,
                'published': advisory.get('published', ''),
                'vulnerable_code': code,
                'fixed_code': '',  # No fix available from description
                'fetch_method': 'description_extraction',
                'is_complete_file': False,
                'quality_score': 0.5,  # Lower quality - may be examples, not real vuln code
                'source': 'advisory_description'
            })
    
    return extracted_examples


def main():
    print("=" * 70)
    print("📝 Extracting Code from Advisory Descriptions")
    print("=" * 70)
    
    advisories_path = 'outputs/datasets/python_advisories.json'
    
    if not os.path.exists(advisories_path):
        print(f"❌ Error: {advisories_path} not found!")
        return
    
    extracted = extract_from_advisories(advisories_path)
    
    print(f"\n✅ Extracted {len(extracted)} code snippets from descriptions")
    
    if extracted:
        # Save extracted examples
        output_path = 'outputs/datasets/description_extracted_code.json'
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(extracted, f, indent=2)
        
        print(f"💾 Saved to {output_path}")
        
        # Show sample
        print(f"\n📋 Sample extracted code:")
        sample = extracted[0]
        print(f"   Advisory: {sample['advisory_id']}")
        print(f"   CWE: {sample['cwe_id']}")
        print(f"   Code preview: {sample['vulnerable_code'][:200]}...")
    else:
        print("⚠️  No code snippets could be extracted from descriptions")


if __name__ == "__main__":
    main()
