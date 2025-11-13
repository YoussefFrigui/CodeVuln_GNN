import json
import re
import requests
import os

INPUT_FILE = 'commit_data_results.json'
OUTPUT_FILE = 'extracted_full_functions.json'
GITHUB_TOKEN = os.environ.get('GITHUB_PAT')
HEADERS = {'Authorization': f'token {GITHUB_TOKEN}'}

def get_file_content(owner, repo, sha, file_path):
    """Fetch full file content from a specific commit."""
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{file_path}?ref={sha}"
    response = requests.get(url, headers=HEADERS)
    if response.status_code == 200:
        content = response.json().get('content', '')
        import base64
        return base64.b64decode(content).decode('utf-8')
    return None

def extract_function_from_file(file_content, line_number):
    """Extract the function containing the given line number."""
    lines = file_content.splitlines()
    if line_number >= len(lines):
        return None
    # Simple heuristic: find 'def ' before the line
    for i in range(line_number, -1, -1):
        if lines[i].strip().startswith('def '):
            # Find the end of the function (next def or end of file)
            func_start = i
            for j in range(func_start + 1, len(lines)):
                if lines[j].strip().startswith('def ') or lines[j].strip().startswith('class '):
                    func_end = j - 1
                    break
            else:
                func_end = len(lines) - 1
            return '\n'.join(lines[func_start:func_end + 1])
    return None

def main():
    with open(INPUT_FILE, 'r', encoding='utf-8') as f:
        commit_results = json.load(f)
    results = []
    for result in commit_results[:10]:  # Limit for testing
        commit_data = result['commit_data']
        if 'files' not in commit_data:
            continue
        for file in commit_data['files']:
            if file['filename'].endswith('.py') and 'patch' in file:
                # Parse patch to find changed lines
                patch = file['patch']
                # Extract line numbers from @@ -old_start,old_count +new_start,new_count @@
                match = re.search(r'@@ -(\d+),\d+ \+(\d+),\d+ @@', patch)
                if match:
                    old_start = int(match.group(1))
                    new_start = int(match.group(2))
                    # Get parent commit SHA
                    parents = commit_data.get('parents', [])
                    if parents:
                        parent_sha = parents[0]['sha']
                        owner_repo = re.search(r'github\.com/([^/]+)/([^/]+)/commit', result['commit_url'])
                        if owner_repo:
                            owner, repo = owner_repo.groups()
                            # Get vulnerable version (before fix)
                            vuln_content = get_file_content(owner, repo, parent_sha, file['filename'])
                            if vuln_content:
                                vuln_func = extract_function_from_file(vuln_content, old_start - 1)  # 0-indexed
                            else:
                                vuln_func = None
                            # Get fixed version (after fix)
                            fixed_content = get_file_content(owner, repo, commit_data['sha'], file['filename'])
                            if fixed_content:
                                fixed_func = extract_function_from_file(fixed_content, new_start - 1)
                            else:
                                fixed_func = None
                            if vuln_func and fixed_func:
                                results.append({
                                    "advisory_id": result['advisory_id'],
                                    "cwe_ids": result['cwe_ids'],
                                    "filename": file['filename'],
                                    "vulnerable_function": vuln_func,
                                    "fixed_function": fixed_func,
                                    "label": "vulnerable"
                                })
    print(f"Extracted {len(results)} full functions.")
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)
    print(f"Saved to {OUTPUT_FILE}")

if __name__ == '__main__':
    main()
