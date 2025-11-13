import json
import ast
import networkx as nx
import torch
from torch_geometric.data import Data, DataLoader
from torch_geometric.utils import from_networkx
import numpy as np
from collections import defaultdict
import re
from sklearn.model_selection import train_test_split
import os
import argparse

# Node type mapping for AST nodes
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

def preprocess_dataset(input_file, max_samples=None, max_nodes=100):
    """Preprocess the labeled dataset for GNN training."""
    print("Loading dataset...")
    with open(input_file, 'r', encoding='utf-8') as f:
        dataset = json.load(f)

    if max_samples:
        dataset = dataset[:max_samples]

    processed_data = []
    successful_parses = 0

    print(f"Processing {len(dataset)} samples...")

    for i, sample in enumerate(dataset):
        if i % 100 == 0:
            print(f"Processed {i}/{len(dataset)} samples...")

        code = sample.get('vulnerable_code', '') or sample.get('patched_code', '')
        if not code or len(code.strip()) == 0:
            continue

        # Parse code to AST
        ast_tree = parse_code_to_ast(code)
        if ast_tree is None:
            continue

        # Convert AST to graph
        graph, node_features, node_labels = ast_to_graph(ast_tree, max_nodes)

        if len(graph.nodes) == 0:
            continue

        # Create label (0: safe, 1: vulnerable)
        label = 1 if sample['label'] == 'vulnerable' else 0

        # Convert to PyTorch Geometric format
        pyg_data = create_pyg_data(graph, node_features, label)
        processed_data.append(pyg_data)
        successful_parses += 1

    print(f"Successfully processed {successful_parses}/{len(dataset)} samples")
    return processed_data

def create_data_loaders(processed_data, batch_size=32, train_ratio=0.7, val_ratio=0.15):
    """Create train/val/test data loaders with stratified sampling."""
    # Separate data by class for stratified splitting
    vulnerable_data = [d for d in processed_data if d.y.item() == 1]
    safe_data = [d for d in processed_data if d.y.item() == 0]

    print(f"Total data: {len(processed_data)} (Vulnerable: {len(vulnerable_data)}, Safe: {len(safe_data)})")

    # Stratified split for vulnerable data
    vuln_train, vuln_temp = train_test_split(vulnerable_data, train_size=train_ratio, random_state=42)
    vuln_val, vuln_test = train_test_split(vuln_temp, train_size=val_ratio/(1-train_ratio), random_state=42)

    # Stratified split for safe data
    safe_train, safe_temp = train_test_split(safe_data, train_size=train_ratio, random_state=42)
    safe_val, safe_test = train_test_split(safe_temp, train_size=val_ratio/(1-train_ratio), random_state=42)

    # Combine stratified splits
    train_data = vuln_train + safe_train
    val_data = vuln_val + safe_val
    test_data = vuln_test + safe_test

    # Shuffle the combined datasets
    import random
    random.shuffle(train_data)
    random.shuffle(val_data)
    random.shuffle(test_data)

    print(f"Train: {len(train_data)} samples (Vuln: {len(vuln_train)}, Safe: {len(safe_train)})")
    print(f"Val: {len(val_data)} samples (Vuln: {len(vuln_val)}, Safe: {len(safe_val)})")
    print(f"Test: {len(test_data)} samples (Vuln: {len(vuln_test)}, Safe: {len(safe_test)})")

    return train_data, val_data, test_data

def main():
    import argparse

    parser = argparse.ArgumentParser(description='Preprocess dataset for GNN training')
    parser.add_argument('--dataset', choices=['original', 'expanded'],
                       default='original', help='Which dataset to use')
    parser.add_argument('--max-samples', type=int, default=None,
                       help='Maximum samples to process (None for all)')

    args = parser.parse_args()

    # Choose dataset file
    if args.dataset == 'expanded':
        INPUT_FILE = 'expanded_labeled_dataset.json'
        print("Using expanded dataset...")
    else:
        INPUT_FILE = 'labeled_dataset.json'
        print("Using original dataset...")

    PROCESSED_DATA_FILE = 'processed_graphs.pt'

    # Check if input file exists
    if not os.path.exists(INPUT_FILE):
        print(f"Error: {INPUT_FILE} not found!")
        if args.dataset == 'expanded':
            print("Run 'python src/expand_dataset.py' first to create the expanded dataset.")
        return

    # Preprocess dataset
    processed_data = preprocess_dataset(INPUT_FILE, max_samples=args.max_samples)

    # Save processed data
    torch.save(processed_data, PROCESSED_DATA_FILE)
    print(f"Saved processed data to {PROCESSED_DATA_FILE}")

    # Create data splits (not loaders yet)
    train_data, val_data, test_data = create_data_loaders(processed_data)

    # Save split data for later use
    torch.save({
        'train_data': train_data,
        'val_data': val_data,
        'test_data': test_data
    }, 'data_splits.pt')
    print("Saved data splits to data_splits.pt")

if __name__ == '__main__':
    main()