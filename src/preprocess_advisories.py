"""
Advisory Preprocessing Pipeline

This script orchestrates the complete preprocessing of GitHub Security Advisories
to extract actual vulnerable Python code. It performs the following steps:

1. Filter Python advisories from GitHub Advisory Database
2. Extract commit URLs from advisory references
3. Fetch commit diffs from GitHub API to get vulnerable code
4. Extract vulnerable code snippets from patches
5. Save processed advisories with vulnerable code for dataset creation

This script must be run BEFORE 01_create_dataset.py to prepare the vulnerable examples.

Usage:
    python scripts/00_preprocess_advisories.py
    
Requirements:
    - GitHub Advisory Database cloned to data/advisory-database/
    - (Optional) GITHUB_PAT environment variable for higher API rate limits
"""

import json
import os
import re
import sys
import time
import requests
from typing import List, Dict, Any
from tqdm import tqdm

# Add project root to path
sys.path.insert(0, os.path.abspath('.'))

GITHUB_TOKEN = os.environ.get('GITHUB_PAT')
HEADERS = {'Authorization': f'token {GITHUB_TOKEN}'} if GITHUB_TOKEN else {}


def extract_code_from_patch(patch_text: str) -> tuple[str, str]:
    """
    Extract vulnerable (removed) and fixed (added) code from a git patch.
    
    Args:
        patch_text: Git diff patch text
        
    Returns:
        Tuple of (vulnerable_code, fixed_code)
    """
    vulnerable_lines = []
    fixed_lines = []
    
    for line in patch_text.split('\n'):
        # Skip patch headers
        if line.startswith('@@') or line.startswith('+++') or line.startswith('---'):
            continue
        
        # Lines removed (vulnerable code)
        if line.startswith('-') and not line.startswith('---'):
            vulnerable_lines.append(line[1:])  # Remove '-' prefix
        
        # Lines added (fixed code)
        elif line.startswith('+') and not line.startswith('+++'):
            fixed_lines.append(line[1:])  # Remove '+' prefix
        
        # Context lines (unchanged)
        elif line.startswith(' '):
            vulnerable_lines.append(line[1:])
            fixed_lines.append(line[1:])
    
    vulnerable_code = '\n'.join(vulnerable_lines).strip()
    fixed_code = '\n'.join(fixed_lines).strip()
    
    return vulnerable_code, fixed_code


def fetch_commit_data(commit_url: str, max_retries: int = 3) -> Dict[str, Any]:
    """
    Fetch commit data from GitHub API.
    
    Args:
        commit_url: GitHub commit or PR URL
        max_retries: Maximum number of retry attempts
        
    Returns:
        Commit data from GitHub API, or None if failed
    """
    # Parse GitHub URL to extract owner, repo, and commit/PR reference
    match = re.search(r'github\.com/([^/]+)/([^/]+)/(commit|pull)/(\w+)', commit_url)
    if not match:
        return None
    
    owner, repo, url_type, ref = match.groups()
    
    # For pull requests, get the last commit
    if url_type == 'pull':
        pr_api_url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{ref}/commits"
        for attempt in range(max_retries):
            try:
                response = requests.get(pr_api_url, headers=HEADERS, timeout=10)
                if response.status_code == 200 and response.json():
                    last_commit_sha = response.json()[-1]['sha']
                    ref = last_commit_sha
                    break
                time.sleep(2)
            except Exception as e:
                if attempt == max_retries - 1:
                    return None
                time.sleep(2)
    
    # Fetch commit data
    api_url = f"https://api.github.com/repos/{owner}/{repo}/commits/{ref}"
    for attempt in range(max_retries):
        try:
            response = requests.get(api_url, headers=HEADERS, timeout=10)
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 403:  # Rate limit
                tqdm.write(f"⚠️  Rate limit hit. Waiting 60 seconds...")
                time.sleep(60)
            else:
                time.sleep(2)
        except Exception as e:
            if attempt == max_retries - 1:
                return None
            time.sleep(2)
    
    return None


def extract_python_vulnerable_code(commit_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Extract vulnerable Python code from commit data.
    
    Args:
        commit_data: GitHub commit API response
        
    Returns:
        List of vulnerable code examples with metadata
    """
    examples = []
    
    if not commit_data or 'files' not in commit_data:
        return examples
    
    for file in commit_data['files']:
        # Only process Python files
        if not file['filename'].endswith('.py'):
            continue
        
        # Skip if no patch available
        if 'patch' not in file:
            continue
        
        # Extract vulnerable and fixed code
        vulnerable_code, fixed_code = extract_code_from_patch(file['patch'])
        
        # Only add if we got actual code (not just comments or whitespace)
        if vulnerable_code and len(vulnerable_code.strip()) > 20:
            examples.append({
                'filename': file['filename'],
                'vulnerable_code': vulnerable_code,
                'fixed_code': fixed_code,
                'changes': file.get('changes', 0),
                'additions': file.get('additions', 0),
                'deletions': file.get('deletions', 0)
            })
    
    return examples


def find_commit_url(advisory: Dict[str, Any]) -> str:
    """
    Find commit or PR URL in advisory references.
    
    Args:
        advisory: GitHub advisory JSON data
        
    Returns:
        Commit or PR URL, or None if not found
    """
    if not advisory.get('references'):
        return None
    
    for ref in advisory['references']:
        url = ref.get('url', '')
        # Match GitHub commit or pull request URLs
        if re.search(r'github\.com/.+/.+/(commit|pull)/\w+', url):
            return url
    
    return None


def process_advisories(
    advisories: List[Dict[str, Any]],
    max_to_process: int = None
) -> List[Dict[str, Any]]:
    """
    Process advisories to extract vulnerable code from commits.
    
    Args:
        advisories: List of GitHub advisory data
        max_to_process: Maximum number of advisories to process (None = all)
        
    Returns:
        List of processed advisories with vulnerable code
    """
    processed_advisories = []
    advisories_to_process = advisories[:max_to_process] if max_to_process else advisories
    
    # Filter advisories that have commit URLs
    advisories_with_commits = []
    print("Filtering advisories with commit URLs...")
    for adv in tqdm(advisories_to_process, desc="Filtering", unit="advisory"):
        commit_url = find_commit_url(adv)
        if commit_url:
            advisories_with_commits.append({
                'advisory_data': adv,
                'commit_url': commit_url
            })
    
    print(f"Found {len(advisories_with_commits)} advisories with commit URLs")
    
    if not advisories_with_commits:
        print("⚠️  No advisories with commit URLs found!")
        return processed_advisories
    
    # Fetch commit data and extract code
    print(f"\nFetching commit data from GitHub API...")
    if not GITHUB_TOKEN:
        print("⚠️  GITHUB_PAT not set. API rate limit: 60 requests/hour")
        print("   Set GITHUB_PAT environment variable for 5000 requests/hour")
    
    for item in tqdm(advisories_with_commits, desc="Fetching commits", unit="commit"):
        adv = item['advisory_data']
        commit_url = item['commit_url']
        
        # Fetch commit data
        commit_data = fetch_commit_data(commit_url)
        
        if not commit_data:
            continue
        
        # Extract vulnerable code
        vulnerable_examples = extract_python_vulnerable_code(commit_data)
        
        if not vulnerable_examples:
            continue
        
        # Store all vulnerable examples from this advisory
        for example in vulnerable_examples:
            processed_advisories.append({
                'advisory_id': adv.get('id', ''),
                'summary': adv.get('summary', ''),
                'severity': adv.get('severity', 'UNKNOWN'),
                'cwe_ids': adv.get('database_specific', {}).get('cwe_ids', []),
                'cvss_score': adv.get('database_specific', {}).get('cvss', {}).get('score', 0),
                'published': adv.get('published', ''),
                'commit_url': commit_url,
                'filename': example['filename'],
                'vulnerable_code': example['vulnerable_code'],
                'fixed_code': example['fixed_code'],
                'changes': example['changes'],
            })
        
        # Rate limiting: sleep 1 second between requests
        time.sleep(1)
    
    return processed_advisories


def main():
    """Main preprocessing pipeline."""
    print("=" * 60)
    print("GitHub Security Advisory Preprocessing Pipeline")
    print("=" * 60)
    
    # Step 1: Load Python advisories
    advisories_path = 'outputs/datasets/python_advisories.json'
    
    if not os.path.exists(advisories_path):
        print(f"\n❌ Error: {advisories_path} not found!")
        print("Please run src/filter_python_advisories.py first:")
        print("  python src/filter_python_advisories.py")
        sys.exit(1)
    
    print(f"\n📂 Loading advisories from {advisories_path}...")
    with open(advisories_path, 'r', encoding='utf-8') as f:
        advisories = json.load(f)
    
    print(f"   Loaded {len(advisories)} Python advisories")
    
    # Step 2: Process advisories to extract vulnerable code
    print(f"\n🔍 Processing advisories to extract vulnerable code...")
    
    # For testing, you can limit: max_to_process=50
    processed_advisories = process_advisories(advisories, max_to_process=None)
    
    print(f"\n✅ Extracted vulnerable code from {len(processed_advisories)} examples")
    
    if not processed_advisories:
        print("\n⚠️  Warning: No vulnerable code extracted!")
        print("   This could be because:")
        print("   - Advisories don't have GitHub commit references")
        print("   - Commits don't contain Python files")
        print("   - GitHub API rate limit reached")
        sys.exit(1)
    
    # Step 3: Save processed advisories
    output_path = 'outputs/datasets/processed_advisories_with_code.json'
    print(f"\n💾 Saving processed advisories to {output_path}...")
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(processed_advisories, f, indent=2)
    
    print(f"   Saved {len(processed_advisories)} vulnerable code examples")
    
    # Print statistics
    print(f"\n📊 Statistics:")
    print(f"   Total examples: {len(processed_advisories)}")
    print(f"   Unique advisories: {len(set(e['advisory_id'] for e in processed_advisories))}")
    print(f"   Unique files: {len(set(e['filename'] for e in processed_advisories))}")
    
    # Print severity distribution
    severity_counts = {}
    for example in processed_advisories:
        severity = example['severity']
        # Handle case where severity might be a list
        if isinstance(severity, list):
            severity = severity[0] if severity else 'UNKNOWN'
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    print(f"\n   Severity distribution:")
    for severity, count in sorted(severity_counts.items()):
        print(f"     {severity}: {count}")
    
    # Print sample
    if processed_advisories:
        print(f"\n📋 Sample vulnerable code example:")
        sample = processed_advisories[0]
        print(f"   Advisory: {sample['advisory_id']}")
        print(f"   File: {sample['filename']}")
        print(f"   Summary: {sample['summary'][:100]}...")
        print(f"   Code length: {len(sample['vulnerable_code'])} characters")
        print(f"   First 200 chars:")
        print(f"   {sample['vulnerable_code'][:200]}...")
    
    print(f"\n✅ Preprocessing complete!")
    print(f"\n📝 Next step: Run dataset creation")
    print(f"   python run_pipeline.py --step preprocess")


if __name__ == "__main__":
    main()
