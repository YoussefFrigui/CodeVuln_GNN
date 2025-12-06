"""
Graph Utilities for Code Representation

This module provides functions for converting Python source code into graph
representations suitable for Graph Neural Network (GNN) models. It focuses
on parsing Abstract Syntax Trees (ASTs) and converting them into NetworkX
graphs, which can then be transformed into PyTorch Geometric data objects.
"""

import ast
from typing import Dict, Any, Tuple, List

import networkx as nx
import torch
from torch_geometric.data import Data
from torch_geometric.utils import from_networkx

# A comprehensive mapping of AST node types to integer identifiers.
# This is used to create one-hot encodings for node features.
NODE_TYPES: Dict[str, int] = {
    "Module": 0, "FunctionDef": 1, "ClassDef": 2, "Return": 3, "Assign": 4,
    "If": 5, "For": 6, "While": 7, "Call": 8, "Name": 9, "Constant": 10,
    "BinOp": 11, "Compare": 12, "List": 13, "Dict": 14, "Attribute": 15,
    "Expr": 16, "Import": 17, "ImportFrom": 18, "With": 19, "Try": 20,
    "ExceptHandler": 21, "Raise": 22, "Assert": 23, "Delete": 24, "AugAssign": 25,
    "AnnAssign": 26, "AsyncFunctionDef": 27, "AsyncFor": 28, "AsyncWith": 29,
    "Await": 30, "Yield": 31, "YieldFrom": 32, "Global": 33, "Nonlocal": 34,
    "Pass": 35, "Break": 36, "Continue": 37, "Slice": 38, "ExtSlice": 39,
    "Index": 40, "Lambda": 41, "Ellipsis": 42, "Starred": 43, "Set": 44,
    "SetComp": 45, "DictComp": 46, "ListComp": 47, "GeneratorExp": 48,
}
# Add a default for unknown node types
UNKNOWN_NODE_TYPE: int = len(NODE_TYPES)

def ast_to_graph(
    ast_tree: ast.AST, max_nodes: int = 100
) -> Tuple[nx.DiGraph, Dict[int, List[float]]]:
    """
    Converts a Python Abstract Syntax Tree (AST) into a NetworkX directed graph.

    Each node in the AST becomes a node in the graph, and edges represent
    parent-child relationships. Node features are extracted based on the AST
    node type and its attributes.

    Args:
        ast_tree: The root of the AST to convert.
        max_nodes: The maximum number of nodes to include in the graph to
                   prevent overly large graphs from complex code.

    Returns:
        A tuple containing:
        - The NetworkX DiGraph.
        - A dictionary mapping node IDs to their feature vectors.
    """
    graph = nx.DiGraph()
    node_id_counter = 0
    node_features: Dict[int, List[float]] = {}

    def traverse(node: ast.AST, parent_id: int = None):
        nonlocal node_id_counter
        if node_id_counter >= max_nodes:
            return

        current_id = node_id_counter
        node_id_counter += 1

        # Node type feature
        node_type = type(node).__name__
        node_type_id = NODE_TYPES.get(node_type, UNKNOWN_NODE_TYPE)
        features = [float(node_type_id)]

        # Add edge from parent to current node
        if parent_id is not None:
            graph.add_edge(parent_id, current_id)

        # Recursively traverse children
        for child in ast.iter_child_nodes(node):
            traverse(child, current_id)

        node_features[current_id] = features

    traverse(ast_tree)
    return graph, node_features


def code_to_pyg_graph(
    code: str, label: int, max_nodes: int = 100, num_node_features: int = 11
) -> Data | None:
    """
    Converts a string of Python code into a PyTorch Geometric Data object.

    This function orchestrates parsing the code into an AST, converting the AST
    to a graph, and then transforming it into a PyG-compatible format.

    Args:
        code: The Python code snippet.
        label: The integer label (e.g., 0 for safe, 1 for vulnerable).
        max_nodes: The maximum number of nodes for the graph.
        num_node_features: The fixed size of the feature vector for each node.

    Returns:
        A PyTorch Geometric `Data` object, or `None` if parsing or
        graph construction fails.
    """
    try:
        ast_tree = ast.parse(code)
        graph, node_features_dict = ast_to_graph(ast_tree, max_nodes=max_nodes)

        if not graph.nodes:
            return None

        # Pad features to ensure consistent feature vector size
        padded_features = []
        for i in sorted(node_features_dict.keys()):
            feature_vec = node_features_dict[i]
            while len(feature_vec) < num_node_features:
                feature_vec.append(0.0)
            padded_features.append(feature_vec[:num_node_features])

        # Convert to PyTorch Geometric format
        pyg_graph = from_networkx(graph)
        pyg_graph.x = torch.tensor(padded_features, dtype=torch.float)
        pyg_graph.y = torch.tensor([label], dtype=torch.long)

        return pyg_graph

    except (SyntaxError, ValueError):
        # Ignore code that fails to parse
        return None
