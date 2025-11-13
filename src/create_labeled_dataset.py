import json
import os
import random

VULNERABLE_FILE = 'extracted_snippets.json'
SAFE_DIR = 'data/python/python/final/jsonl/train/'
OUTPUT_FILE = 'labeled_dataset.json'
NUM_SAFE = 10000  # Number of safe examples to sample

def load_vulnerable():
    with open(VULNERABLE_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)

def sample_safe_examples(safe_dir, num_samples):
    safe_examples = []
    jsonl_files = [f for f in os.listdir(safe_dir) if f.endswith('.jsonl')]
    all_lines = []
    for file in jsonl_files:
        with open(os.path.join(safe_dir, file), 'r', encoding='utf-8') as f:
            all_lines.extend(f.readlines())
    random.shuffle(all_lines)
    for line in all_lines[:num_samples]:
        try:
            data = json.loads(line.strip())
            safe_examples.append({
                "advisory_id": None,
                "cwe_ids": [],
                "filename": data.get('path', ''),
                "vulnerable_code": "",
                "patched_code": data['code'],
                "label": "safe"
            })
        except json.JSONDecodeError:
            continue
    return safe_examples

def main():
    vulnerable = load_vulnerable()
    print(f"Loaded {len(vulnerable)} vulnerable examples.")
    safe = sample_safe_examples(SAFE_DIR, NUM_SAFE)
    print(f"Sampled {len(safe)} safe examples.")
    dataset = vulnerable + safe
    random.shuffle(dataset)
    print(f"Total dataset: {len(dataset)} examples.")
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(dataset, f, indent=2)
    print(f"Saved labeled dataset to {OUTPUT_FILE}")

if __name__ == '__main__':
    main()
