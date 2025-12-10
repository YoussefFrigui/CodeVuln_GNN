# GNN Model Architecture

This document describes the Graph Neural Network architecture used for Python vulnerability detection.

## Overview

The model converts Python code into Abstract Syntax Tree (AST) graphs, then uses a multi-layer GNN to classify code as vulnerable or safe.

```
Python Code → AST → NetworkX Graph → PyG Data → GNN → Binary Classification
```

## Model Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    VulnerabilityGNN                              │
├─────────────────────────────────────────────────────────────────┤
│  Input: Node Features (11-dim) + Edge Index                     │
│                           ↓                                      │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ GCN Layers (4x)                                             ││
│  │   GCNConv(in, hidden) → BatchNorm → ReLU → Dropout          ││
│  │   GCNConv(hidden, hidden) → BatchNorm → ReLU → Dropout      ││
│  │   ...                                                        ││
│  └─────────────────────────────────────────────────────────────┘│
│                           ↓                                      │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ GAT Attention Layer                                         ││
│  │   GATConv(hidden, hidden, heads=4)                          ││
│  └─────────────────────────────────────────────────────────────┘│
│                           ↓                                      │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ Global Mean Pooling                                         ││
│  │   Aggregates all node features into single graph embedding  ││
│  └─────────────────────────────────────────────────────────────┘│
│                           ↓                                      │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ MLP Classifier                                              ││
│  │   Linear(hidden*heads, hidden) → ReLU → Dropout             ││
│  │   Linear(hidden, 2) → Softmax                               ││
│  └─────────────────────────────────────────────────────────────┘│
│                           ↓                                      │
│  Output: [P(safe), P(vulnerable)]                               │
└─────────────────────────────────────────────────────────────────┘
```

## Configuration

All model parameters are in `configs/base_config.yaml`:

```yaml
model:
  num_node_features: 11    # AST node type features
  hidden_channels: 128     # Hidden layer size
  num_classes: 2           # Binary classification
  gcn_layers: 4            # Number of GCN layers
  gat_heads: 4             # Multi-head attention
  dropout: 0.5             # Dropout rate
```

## Node Features

Each AST node is encoded as an 11-dimensional vector:
- **Position 0**: AST node type ID (0-48)
- **Positions 1-10**: Reserved for future features (currently zero-padded)

### AST Node Types

```python
NODE_TYPES = {
    'Module': 0, 'FunctionDef': 1, 'AsyncFunctionDef': 2,
    'ClassDef': 3, 'Return': 4, 'Delete': 5, 'Assign': 6,
    'AugAssign': 7, 'AnnAssign': 8, 'For': 9, 'AsyncFor': 10,
    'While': 11, 'If': 12, 'With': 13, 'AsyncWith': 14,
    'Raise': 15, 'Try': 16, 'Assert': 17, 'Import': 18,
    'ImportFrom': 19, 'Global': 20, 'Nonlocal': 21, 'Expr': 22,
    'Pass': 23, 'Break': 24, 'Continue': 25, 'BoolOp': 26,
    'BinOp': 27, 'UnaryOp': 28, 'Lambda': 29, 'IfExp': 30,
    'Dict': 31, 'Set': 32, 'ListComp': 33, 'SetComp': 34,
    'DictComp': 35, 'GeneratorExp': 36, 'Await': 37, 'Yield': 38,
    'YieldFrom': 39, 'Compare': 40, 'Call': 41, 'FormattedValue': 42,
    'JoinedStr': 43, 'Constant': 44, 'Attribute': 45, 'Subscript': 46,
    'Starred': 47, 'Name': 48, 'List': 49, 'Tuple': 50
}
```

## Graph Structure

- **Nodes**: AST nodes (statements, expressions, etc.)
- **Edges**: Parent-child relationships in the AST (directed)
- **Max nodes**: 100 per graph (configurable via `max_nodes_per_graph`)

## Why This Architecture?

### GCN Layers (4x)
- Captures structural patterns in the AST
- Each layer aggregates information from neighbors
- 4 layers = each node "sees" 4 hops in the graph

### GAT Attention
- Learns which neighboring nodes are most important
- Multi-head attention captures different relationship types
- Helps focus on security-relevant patterns (e.g., user input → sink)

### Global Mean Pooling
- Creates fixed-size graph embedding regardless of graph size
- Mean (vs max/sum) provides normalized representation

### MLP Classifier
- Two-layer MLP for final classification
- Dropout prevents overfitting to training patterns

## Training Details

### Loss Function
Weighted Cross-Entropy to handle class imbalance (~1:50 ratio):

```python
# Weight calculation
weight_safe = total / (2 * num_safe)       # ~0.5
weight_vuln = total / (2 * num_vulnerable) # ~26.0
```

### Optimizer
- AdamW with weight decay (0.01)
- Learning rate: 0.001 (configurable)

### Early Stopping
- Monitors validation loss
- Patience: 5 epochs (configurable)
- Restores best model weights

## Memory Requirements

| Batch Size | GPU Memory | Notes |
|------------|------------|-------|
| 64 | ~6-8 GB | Default setting |
| 32 | ~4-5 GB | For 6GB GPUs |
| 16 | ~2-3 GB | For 4GB GPUs |
| 8 | ~1-2 GB | Minimum viable |

Reduce `batch_size` in config if you get OOM errors.

## Extending the Model

### Adding Edge Features
1. Modify `graph_utils.py` to compute edge attributes
2. Change GCNConv → edge-aware variant (e.g., GINEConv)
3. Update model input handling

### Using Different GNN Layers
Options in PyTorch Geometric:
- `GraphSAGE` - For very large graphs
- `GIN` - Better theoretical expressiveness  
- `TransformerConv` - Attention-based alternative

### Adding Node Features
1. Extend `NODE_TYPES` dict in `graph_utils.py`
2. Add feature computation (e.g., variable names, scopes)
3. Update `num_node_features` in config
4. Regenerate dataset (`.pt` files)

## Model File Reference

| File | Description |
|------|-------------|
| `src/modeling/model.py` | Model class definition |
| `src/data_processing/graph_utils.py` | Code → Graph conversion |
| `src/train_gnn.py` | Training loop |
| `configs/base_config.yaml` | All hyperparameters |
| `outputs/models/trained_gnn_model.pt` | Saved model weights |
