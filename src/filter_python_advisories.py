import os
import json
from glob import glob
from tqdm import tqdm

ADVISORY_PATH = r'data/advisory-database/advisories/github-reviewed/'
OUTPUT_FILE = 'outputs/datasets/python_advisories.json'

def find_python_advisories(advisory_path, max_files=None):
    python_advisories = []
    json_files = glob(os.path.join(advisory_path, '**/*.json'), recursive=True)
    total_files = len(json_files)
    print(f"Scanning {total_files} advisory files...")
    
    # Use tqdm for progress tracking
    files_to_process = json_files[:max_files] if max_files else json_files
    for file_path in tqdm(files_to_process, desc="Scanning advisories", unit="file"):
        file_path = os.path.normpath(file_path)
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                advisory = json.load(f)
                if advisory.get('affected'):
                    if advisory['affected'][0].get('package', {}).get('ecosystem') == 'PyPI':
                        python_advisories.append(advisory)
        except json.JSONDecodeError:
            tqdm.write(f"Warning: Could not decode JSON from {file_path}")
    return python_advisories

if __name__ == '__main__':
    # Set max_files to None for full scan, or an integer for batch/early stopping
    max_files = None  # Change this value for batch size or None for all
    all_python_advisories = find_python_advisories(ADVISORY_PATH, max_files=max_files)
    print(f"Found {len(all_python_advisories)} Python-related security advisories.")
    # Optionally print the first advisory for inspection
    if all_python_advisories:
        print(json.dumps(all_python_advisories[0], indent=2))
    # Save to file
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(all_python_advisories, f, indent=2)
    print(f"Saved Python advisories to {OUTPUT_FILE}")
