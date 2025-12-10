# Configuration Reference

All runtime parameters are controlled via `configs/base_config.yaml`. Never hardcode paths or hyperparameters in code.

## Configuration Structure

```yaml
# Data paths and parameters
data:
  advisories_path: "outputs/datasets/merged_vulnerabilities.json"
  codesearchnet_path: "data/python/python/final/jsonl/"
  output_dir: "outputs"
  
dataset:
  max_safe_examples: 200000
  max_nodes_per_graph: 100
  use_curated_vulnerabilities: false

# Model architecture
model:
  num_node_features: 11
  hidden_channels: 128
  num_classes: 2
  gcn_layers: 4
  gat_heads: 4
  dropout: 0.5

# Training settings  
training:
  num_epochs: 50
  batch_size: 64
  learning_rate: 0.001
  patience: 5
  device: "auto"
  random_state: 42
```

## Parameter Reference

### Data Section

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `advisories_path` | string | `outputs/datasets/merged_vulnerabilities.json` | Path to vulnerability JSON |
| `codesearchnet_path` | string | `data/python/python/final/jsonl/` | Path to safe code examples |
| `output_dir` | string | `outputs` | Base directory for all outputs |

### Dataset Section

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `max_safe_examples` | int | 200000 | Maximum safe examples to use |
| `max_nodes_per_graph` | int | 100 | Truncate large ASTs |
| `use_curated_vulnerabilities` | bool | false | Use curated examples (already in merged file) |

### Model Section

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `num_node_features` | int | 11 | Dimension of node feature vectors |
| `hidden_channels` | int | 128 | Hidden layer width |
| `num_classes` | int | 2 | Output classes (safe/vulnerable) |
| `gcn_layers` | int | 4 | Number of GCN layers |
| `gat_heads` | int | 4 | GAT attention heads |
| `dropout` | float | 0.5 | Dropout probability |

### Training Section

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `num_epochs` | int | 50 | Maximum training epochs |
| `batch_size` | int | 64 | Samples per batch |
| `learning_rate` | float | 0.001 | Adam learning rate |
| `patience` | int | 5 | Early stopping patience |
| `device` | string | `auto` | `auto`, `cuda`, or `cpu` |
| `random_state` | int | 42 | Random seed for reproducibility |

## Common Modifications

### Reduce Memory Usage
```yaml
training:
  batch_size: 32  # or 16
dataset:
  max_nodes_per_graph: 50
```

### Speed Up Development
```yaml
dataset:
  max_safe_examples: 10000  # Smaller dataset
training:
  num_epochs: 10
```

### Improve Model Capacity
```yaml
model:
  hidden_channels: 256
  gcn_layers: 6
  gat_heads: 8
```

### Debug Class Imbalance
```yaml
dataset:
  max_safe_examples: 4000  # Match vulnerable count
```

## Accessing Config in Code

```python
import yaml

def load_config(config_path: str = "configs/base_config.yaml") -> dict:
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)

config = load_config()
batch_size = config['training']['batch_size']
```

## Environment Variables

Some scripts also check environment variables:

| Variable | Purpose |
|----------|---------|
| `GITHUB_TOKEN` | GitHub API authentication for fetching code |
| `MLFLOW_TRACKING_URI` | MLflow server URL (optional) |

## Output Directory Structure

Based on `output_dir` setting:

```
outputs/
├── datasets/
│   ├── merged_vulnerabilities.json
│   ├── final_graph_dataset.pt
│   └── data_splits.pt
├── models/
│   └── trained_gnn_model.pt
├── cache/
│   └── *.json (GitHub API cache)
└── mlruns/
    └── (MLflow experiment data)
```

## Validation

The pipeline validates config on startup:
- Checks required paths exist
- Validates numeric ranges
- Warns about incompatible settings

If you see "Config validation failed", check:
1. Paths exist and are readable
2. Numeric values are positive
3. Device setting matches available hardware
