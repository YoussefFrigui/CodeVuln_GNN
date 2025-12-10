"""Quick check of advisories without commit URLs."""
import json
import re

data = json.load(open('outputs/datasets/python_advisories.json'))

def has_commit_url(adv):
    for ref in adv.get('references', []):
        url = ref.get('url', '')
        if re.search(r'github\.com/.+/.+/(commit|pull)/\w+', url):
            return True
    return False

with_commits = [a for a in data if has_commit_url(a)]
no_commits = [a for a in data if not has_commit_url(a)]

print(f"Total advisories: {len(data)}")
print(f"With commit URLs: {len(with_commits)}")
print(f"Without commit URLs: {len(no_commits)}")

if no_commits:
    print("\n--- Sample advisory WITHOUT commit ---")
    sample = no_commits[0]
    print(f"ID: {sample.get('id')}")
    print(f"Summary: {sample.get('summary', '')[:100]}...")
    print(f"Severity: {sample.get('severity')}")
    print(f"References:")
    for ref in sample.get('references', [])[:5]:
        print(f"  - {ref.get('url', '')}")
    
    # Check if any have code in description or elsewhere
    print("\n--- Checking for code in descriptions ---")
    has_code_block = 0
    for adv in no_commits:
        desc = adv.get('details', '') or adv.get('description', '') or ''
        if '```' in desc or 'def ' in desc or 'import ' in desc:
            has_code_block += 1
    print(f"Advisories with code in description: {has_code_block}/{len(no_commits)}")
