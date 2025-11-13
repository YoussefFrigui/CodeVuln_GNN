import json
import ast
import requests
import os

INPUT_FILE = 'commit_data_results.json'
OUTPUT_FILE = 'extracted_full_functions.json'
GITHUB_TOKEN = os.environ.get('GITHUB_PAT')
HEADERS = {'Authorization': f'token {GITHUB_TOKEN}'}

def get_file_content(raw_url):
    response = requests.get(raw_url, headers=HEADERS)
    if response.status_code == 200:
        return response.text
    return None

def find_function_at_line(source_code, line_number):
    try:
        tree = ast.parse(source_code)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.lineno <= line_number <= (node.end_lineno or node.lineno):
                # Get the source lines for this function
                lines = source_code.splitlines()
                start = node.lineno - 1  # 0-based
                end = node.end_lineno if node.end_lineno else len(lines)
                return "\n".join(lines[start:end])
    except SyntaxError:
        pass
    return None

def extract_full_functions(commit_data, file_info):
    patch_text = file_info['patch']
    filename = file_info['filename']
    
    # Get before and after file contents
    after_content = get_file_content(file_info['raw_url'])
    if not after_content:
        return None, None
    
    # For before, get parent commit SHA
    parents = commit_data.get('parents', [])
    if not parents:
        return None, after_content  # If no parent, before is empty
    
    parent_sha = parents[0]['sha']
    # Construct before URL
    before_url = file_info['raw_url'].replace(commit_data['sha'], parent_sha)
    before_content = get_file_content(before_url)
    if not before_content:
        before_content = ""  # Assume new file
    
    # Parse patch to find changed line numbers
    changed_lines = []
    for line in patch_text.splitlines():
        if line.startswith('@@'):
            # @@ -start,count +start,count @@
            parts = line.split()
            if len(parts) >= 3:
                before_part = parts[1]  # -start,count
                start_line = int(before_part.split(',')[0][1:])  # Remove -
                changed_lines.append(start_line)
    
    if not changed_lines:
        return None, None
    
    # Find function at the first changed line
    vulnerable_function = find_function_at_line(before_content, changed_lines[0])
    patched_function = find_function_at_line(after_content, changed_lines[0])
    
    return vulnerable_function, patched_function

def main():
    with open(INPUT_FILE, 'r', encoding='utf-8') as f:
        commit_results = json.load(f)
    dataset = []
    count = 0
    for result in commit_results[:5]:  # Process only first 5 for testing
        print(f"Processing advisory {count+1}")
        count += 1
        advisory_id = result['advisory_id']
        cwe_ids = result['cwe_ids']
        summary = result['summary']
        commit_data = result['commit_data']
        if 'files' not in commit_data:
            continue
        for file in commit_data['files']:
            if file['filename'].endswith('.py') and 'patch' in file:
                print(f"  Extracting from {file['filename']}")
                vulnerable_func, patched_func = extract_full_functions(commit_data, file)
                if vulnerable_func:
                    dataset.append({
                        "advisory_id": advisory_id,
                        "cwe_ids": cwe_ids,
                        "filename": file['filename'],
                        "vulnerable_code": vulnerable_func,
                        "patched_code": patched_func or "",
                        "label": "vulnerable"
                    })
                if patched_func and patched_func != vulnerable_func:
                    dataset.append({
                        "advisory_id": advisory_id,
                        "cwe_ids": cwe_ids,
                        "filename": file['filename'],
                        "vulnerable_code": "",
                        "patched_code": patched_func,
                        "label": "patched"
                    })
    print(f"Extracted {len(dataset)} data points.")
    if dataset:
        print(json.dumps(dataset[0], indent=2))
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(dataset, f, indent=2)
    print(f"Saved extracted full functions to {OUTPUT_FILE}")

if __name__ == '__main__':
    main()
