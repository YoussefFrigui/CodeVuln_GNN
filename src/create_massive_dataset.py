#!/usr/bin/env python3
"""
Create Massive Training Dataset from Full CodeSearchNet + Advisories
Uses all CodeSearchNet training data as safe examples + all advisories as vulnerable examples
"""

import json
import os
import random
from pathlib import Path
import torch
from torch_geometric.data import Data
from torch_geometric.utils import from_networkx
import networkx as nx
import ast

# Node type mapping for AST nodes (same as preprocess_data.py)
NODE_TYPES = {
    'Module': 0, 'FunctionDef': 1, 'ClassDef': 2, 'Return': 3, 'Assign': 4,
    'If': 5, 'For': 6, 'While': 7, 'Call': 8, 'Name': 9, 'Constant': 10,
    'BinOp': 11, 'Compare': 12, 'List': 13, 'Dict': 14, 'Attribute': 15,
    'Expr': 16, 'Import': 17, 'ImportFrom': 18, 'With': 19, 'Try': 20,
    'ExceptHandler': 21, 'Raise': 22, 'Assert': 23, 'Delete': 24, 'AugAssign': 25,
    'AnnAssign': 26, 'AsyncFunctionDef': 27, 'AsyncFor': 28, 'AsyncWith': 29,
    'Await': 30, 'Yield': 31, 'YieldFrom': 32, 'Global': 33, 'Nonlocal': 34,
    'Pass': 35, 'Break': 36, 'Continue': 37, 'Slice': 38, 'ExtSlice': 39,
    'Index': 40, 'Lambda': 41, 'Ellipsis': 42, 'Starred': 43, 'Set': 44,
    'SetComp': 45, 'DictComp': 46, 'ListComp': 47, 'GeneratorExp': 48
}

def parse_code_to_ast(code):
    """Parse Python code string to AST."""
    try:
        return ast.parse(code)
    except SyntaxError:
        return None

def ast_to_graph(ast_tree, max_nodes=100):
    """Convert AST to NetworkX graph with node features."""
    G = nx.DiGraph()
    node_id = 0
    node_features = {}
    node_labels = {}

    def traverse_ast(node, parent_id=None):
        nonlocal node_id
        if node_id >= max_nodes:
            return

        # Create node features
        node_type = type(node).__name__
        node_type_id = NODE_TYPES.get(node_type, len(NODE_TYPES))

        # Extract additional features
        features = [node_type_id]

        # Add text content for certain node types
        if hasattr(node, 'name') and node.name is not None:
            features.extend([float(ord(c)) if c.isascii() else 0.0 for c in str(node.name)[:10].ljust(10)])
        elif hasattr(node, 'id') and node.id is not None:
            features.extend([float(ord(c)) if c.isascii() else 0.0 for c in str(node.id)[:10].ljust(10)])
        elif hasattr(node, 'value') and node.value is not None and isinstance(node.value, str):
            features.extend([float(ord(c)) if c.isascii() else 0.0 for c in str(node.value)[:10].ljust(10)])
        elif hasattr(node, 'value') and node.value is not None and isinstance(node.value, (int, float)):
            features.extend([float(node.value) if abs(float(node.value)) < 1000 else 0.0] + [0.0]*9)
        else:
            features.extend([0.0] * 10)

        # Pad features to fixed size
        while len(features) < 11:
            features.append(0.0)

        node_features[node_id] = features
        node_labels[node_id] = node_type

        current_id = node_id
        node_id += 1

        # Add edge to parent
        if parent_id is not None:
            G.add_edge(parent_id, current_id)

        # Recursively traverse children
        for child in ast.iter_child_nodes(node):
            traverse_ast(child, current_id)

    traverse_ast(ast_tree)
    return G, node_features, node_labels

def create_pyg_data(graph, node_features, label):
    """Convert NetworkX graph to PyTorch Geometric Data object."""
    # Convert to PyTorch Geometric format
    data = from_networkx(graph)

    # Add node features
    x = torch.tensor(list(node_features.values()), dtype=torch.float)
    data.x = x

    # Add label
    data.y = torch.tensor([label], dtype=torch.long)

    return data

def load_vulnerable_examples():
    """Load all vulnerable examples from advisories."""
    print("Loading advisories data...")
    advisories_data = []
    try:
        with open('python_advisories.json', 'r', encoding='utf-8') as f:
            advisories_data = json.load(f)
    except FileNotFoundError:
        print("Warning: python_advisories.json not found")
        return []

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
            summary = advisory['summary']
            if len(summary) > 20:
                # Create a simple Python function with the vulnerability description
                code_sources.append(f"def vulnerable_function():\n    # {summary}\n    pass")

        # Also try to extract from description if available
        if not code_sources and 'description' in advisory:
            description = advisory['description']
            if len(description) > 20:
                # Create a simple Python function with the security issue
                code_sources.append(f"def security_issue():\n    # {description[:100]}...\n    pass")

        # If still no code sources, create a synthetic example from CWE and package info
        if not code_sources:
            cwe_info = ', '.join(advisory.get('cwe_ids', []))
            package_info = advisory.get('affected', [{}])[0].get('package', {}).get('name', 'unknown')
            synthetic_code = f"def vulnerable_package_{package_info.replace('-', '_')}():\n    # Vulnerability in {package_info}: {cwe_info}\n    pass"
            if cwe_info or package_info != 'unknown':
                code_sources.append(synthetic_code)

        # Create examples from all code sources
        for code in code_sources:
            if code.strip() and len(code.strip()) > 20:  # Ensure minimum length
                example = {
                    'code': code,
                    'label': 1  # vulnerable
                }
                vulnerable_examples.append(example)

    print(f"Loaded {len(vulnerable_examples)} vulnerable examples")
    return vulnerable_examples

def load_codesearchnet_examples(max_samples=100000):
    """Load safe examples from full CodeSearchNet dataset."""
    safe_examples = []

    # CodeSearchNet data directories
    data_dirs = [
        'data/python/python/final/jsonl/train',
        'data/python/python/final/jsonl/valid',
        'data/python/python/final/jsonl/test'
    ]

    samples_collected = 0

    for data_dir in data_dirs:
        if not os.path.exists(data_dir):
            print(f"Warning: {data_dir} not found, skipping...")
            continue

        jsonl_files = list(Path(data_dir).glob('*.jsonl'))
        random.shuffle(jsonl_files)  # Randomize file order

        print(f"Processing {len(jsonl_files)} files from {data_dir}")

        for jsonl_file in jsonl_files:
            try:
                with open(jsonl_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        if samples_collected >= max_samples:
                            break

                        try:
                            sample = json.loads(line.strip())
                            code = sample.get('code', '').strip()

                            # Filter for reasonable code length and quality
                            if (50 <= len(code) <= 2000 and
                                code.count('\n') >= 3 and
                                'def ' in code):  # Must contain function definition

                                example = {
                                    'code': code,
                                    'label': 0  # safe
                                }
                                safe_examples.append(example)
                                samples_collected += 1

                                if samples_collected % 10000 == 0:
                                    print(f"Loaded {samples_collected} safe examples...")

                        except json.JSONDecodeError:
                            continue

            except Exception as e:
                print(f"Error processing {jsonl_file}: {e}")
                continue

            if samples_collected >= max_samples:
                break

        if samples_collected >= max_samples:
            break

    print(f"Loaded {len(safe_examples)} safe examples from CodeSearchNet")
    return safe_examples

def process_examples_to_graphs(examples, label, max_samples=None):
    """Process code examples into PyTorch Geometric graphs."""
    processed_data = []
    successful_parses = 0

    if max_samples:
        examples = examples[:max_samples]

    print(f"Processing {len(examples)} examples with label {label}...")

    for i, example in enumerate(examples):
        if i % 500 == 0 and i > 0:
            print(f"Processed {i}/{len(examples)} examples...")

        code = example['code']
        if not code or len(code.strip()) == 0:
            continue

        # Parse code to AST
        ast_tree = parse_code_to_ast(code)
        if ast_tree is None:
            continue

        # Convert AST to graph
        graph, node_features, node_labels = ast_to_graph(ast_tree, max_nodes=100)

        if len(graph.nodes) == 0:
            continue

        # Convert to PyTorch Geometric format
        pyg_data = create_pyg_data(graph, node_features, label)
        processed_data.append(pyg_data)
        successful_parses += 1

    print(f"Successfully processed {successful_parses}/{len(examples)} examples")
    return processed_data

def create_massive_dataset(vulnerable_examples, safe_examples, vuln_ratio=0.1):
    """Create massive dataset with controlled vulnerable-to-safe ratio."""
    total_safe = len(safe_examples)
    target_vuln = int(total_safe * vuln_ratio)

    # Limit vulnerable examples to maintain ratio
    vulnerable_examples = vulnerable_examples[:target_vuln]

    print(f"Creating dataset with {len(vulnerable_examples)} vulnerable and {len(safe_examples)} safe examples")

    # Combine datasets
    all_examples = vulnerable_examples + safe_examples

    # Shuffle the dataset
    random.shuffle(all_examples)

    print(f"Final dataset: {len(all_examples)} examples")
    vuln_count = sum(1 for ex in all_examples if ex.y.item() == 1)
    safe_count = len(all_examples) - vuln_count
    print(".2f")

    return all_examples

def save_massive_dataset(examples, filename='massive_codesearchnet_dataset.pt'):
    """Save the massive dataset."""
    torch.save(examples, filename)
    print(f"Saved massive dataset to {filename}")
    return filename

def main():
    print("Creating Massive CodeSearchNet + Advisories Dataset")
    print("=" * 60)

    # Load vulnerable examples
    vulnerable_examples = load_vulnerable_examples()

    # Load safe examples from full CodeSearchNet
    print("Loading CodeSearchNet examples (this may take a while)...")
    safe_examples = load_codesearchnet_examples(max_samples=200000)  # Large sample

    # Process examples into PyTorch Geometric graphs
    print("Processing vulnerable examples into graphs...")
    vulnerable_graphs = process_examples_to_graphs(vulnerable_examples, label=1)

    print("Processing safe examples into graphs...")
    safe_graphs = process_examples_to_graphs(safe_examples, label=0)

    # Create massive dataset
    print("Creating massive dataset...")
    massive_dataset = create_massive_dataset(vulnerable_graphs, safe_graphs, vuln_ratio=0.05)

    # Save the dataset
    save_massive_dataset(massive_dataset)

    print("\n" + "=" * 60)
    print("Massive Dataset Creation Complete!")
    print(f"Dataset saved as: massive_codesearchnet_dataset.pt")
    print(f"Total examples: {len(massive_dataset)}")
    print("\nNext steps:")
    print("1. Use this dataset for training: python src/train_on_massive.py")
    print("2. This will create a much more robust model!")

if __name__ == '__main__':
    main()