#!/usr/bin/env python3
"""
Expand Dataset for Better GNN Training
Creates a much larger and more diverse dataset using all available data
"""

import json
import os
import random
from pathlib import Path

def load_json_file(filepath):
    """Load JSON file safely."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Warning: {filepath} not found")
        return []
    except json.JSONDecodeError as e:
        print(f"Error loading {filepath}: {e}")
        return []

def extract_vulnerable_examples_from_advisories(advisories_data):
    """Extract vulnerable examples from all advisories (with and without commits)."""
    vulnerable_examples = []

    for advisory in advisories_data:
        # Try to get code from various sources
        code_sources = []

        # 1. From commit data if available
        if 'references' in advisory:
            for ref in advisory.get('references', []):
                if 'commit_data' in ref and ref['commit_data']:
                    for file_change in ref['commit_data'].get('files', []):
                        if file_change.get('patch'):
                            # Extract vulnerable lines (removed lines starting with -)
                            patch_lines = file_change['patch'].split('\n')
                            vulnerable_code = []
                            for line in patch_lines:
                                if line.startswith('-') and not line.startswith('---'):
                                    vulnerable_code.append(line[1:].strip())  # Remove the -

                            if vulnerable_code:
                                code_sources.append('\n'.join(vulnerable_code))

        # 2. From advisory summary/description (as fallback)
        if not code_sources and 'summary' in advisory:
            # Use summary as synthetic vulnerable example
            summary = advisory['summary']
            if len(summary) > 20:  # Only use substantial summaries
                code_sources.append(f"# Potential vulnerability: {summary}")

        # Also try to extract from description if available
        if not code_sources and 'description' in advisory:
            description = advisory['description']
            if len(description) > 20:
                code_sources.append(f"# Security issue: {description}")

        # If still no code sources, create a synthetic example from CWE and package info
        if not code_sources:
            cwe_info = ', '.join(advisory.get('cwe_ids', []))
            package_info = advisory.get('affected', [{}])[0].get('package', {}).get('name', 'unknown')
            synthetic_code = f"# Vulnerability in {package_info}: {cwe_info}"
            if cwe_info or package_info != 'unknown':
                code_sources.append(synthetic_code)

        # Create examples from all code sources
        for code in code_sources:
            if code.strip():
                example = {
                    'advisory_id': advisory.get('id', ''),
                    'cwe_ids': advisory.get('cwe_ids', []),
                    'filename': 'synthetic_vulnerable.py',  # Generic filename
                    'vulnerable_code': code,
                    'patched_code': '',  # No patched version for non-commit advisories
                    'label': 'vulnerable',
                    'source': 'advisory_expanded'
                }
                vulnerable_examples.append(example)

    return vulnerable_examples

def extract_safe_examples_from_codesearchnet(max_samples=50000):
    """Extract safe examples from CodeSearchNet dataset."""
    safe_examples = []

    # CodeSearchNet data directories
    data_dirs = [
        'data/python/python/final/jsonl/train',
        'data/python/python/final/jsonl/valid',
        'data/python/python/final/jsonl/test'
    ]

    files_processed = 0
    samples_collected = 0

    for data_dir in data_dirs:
        if not os.path.exists(data_dir):
            continue

        jsonl_files = list(Path(data_dir).glob('*.jsonl'))
        random.shuffle(jsonl_files)  # Randomize file order

        for jsonl_file in jsonl_files:
            try:
                with open(jsonl_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        if samples_collected >= max_samples:
                            break

                        try:
                            sample = json.loads(line.strip())
                            code = sample.get('code', '').strip()

                            # Filter for reasonable code length
                            if 50 <= len(code) <= 2000 and code.count('\n') >= 3:
                                example = {
                                    'filename': f"safe_{samples_collected}.py",
                                    'vulnerable_code': code,
                                    'patched_code': '',
                                    'label': 'safe',
                                    'source': 'codesearchnet_expanded'
                                }
                                safe_examples.append(example)
                                samples_collected += 1

                        except json.JSONDecodeError:
                            continue

            except Exception as e:
                print(f"Error processing {jsonl_file}: {e}")
                continue

            if samples_collected >= max_samples:
                break

        if samples_collected >= max_samples:
            break

    return safe_examples

def create_balanced_dataset(vulnerable_examples, safe_examples, target_safe_ratio=2.0):
    """Create a balanced dataset with appropriate safe-to-vulnerable ratio."""
    num_vulnerable = len(vulnerable_examples)
    target_safe = int(num_vulnerable * target_safe_ratio)

    # Limit safe examples to target amount
    safe_examples = safe_examples[:target_safe]

    # Combine datasets
    combined_dataset = vulnerable_examples + safe_examples

    # Shuffle the dataset
    random.shuffle(combined_dataset)

    print(f"Created dataset with {len(combined_dataset)} samples:")
    print(f"  - Vulnerable: {num_vulnerable}")
    print(f"  - Safe: {len(safe_examples)}")
    print(".2f")

    return combined_dataset

def save_expanded_dataset(dataset, output_file='expanded_labeled_dataset.json'):
    """Save the expanded dataset."""
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(dataset, f, indent=2, ensure_ascii=False)

    print(f"Saved expanded dataset to {output_file}")
    return output_file

def main():
    print("Expanding Dataset for Better GNN Training")
    print("=" * 50)

    # Load existing data
    print("Loading existing data...")
    advisories_data = load_json_file('python_advisories.json')
    print(f"Loaded {len(advisories_data)} advisories")

    # Extract vulnerable examples from all advisories
    print("Extracting vulnerable examples from all advisories...")
    vulnerable_examples = extract_vulnerable_examples_from_advisories(advisories_data)
    print(f"Extracted {len(vulnerable_examples)} vulnerable examples")

    # Extract safe examples from CodeSearchNet
    print("Extracting safe examples from CodeSearchNet...")
    safe_examples = extract_safe_examples_from_codesearchnet(max_samples=50000)
    print(f"Extracted {len(safe_examples)} safe examples")

    # Create balanced dataset
    print("Creating balanced dataset...")
    expanded_dataset = create_balanced_dataset(vulnerable_examples, safe_examples, target_safe_ratio=3.0)

    # Save expanded dataset
    output_file = save_expanded_dataset(expanded_dataset)

    print("\n" + "=" * 50)
    print("Dataset Expansion Complete!")
    print(f"Original dataset: 15,551 samples")
    print(f"Expanded dataset: {len(expanded_dataset)} samples")
    print(".1f")
    print("\nNext steps:")
    print("1. Update preprocess_data.py to use the expanded dataset")
    print("2. Retrain the model with more data")
    print("3. Evaluate performance improvement")

if __name__ == '__main__':
    main()