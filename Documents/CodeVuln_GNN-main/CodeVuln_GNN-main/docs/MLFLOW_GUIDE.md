# MLflow Integration Guide

## Overview

This project uses **MLflow** to track experiments, log metrics, manage models, and enable reproducibility. Every training run automatically logs:

- 📊 **Metrics**: Training/validation/test loss, accuracy, precision, recall, F1
- ⚙️ **Parameters**: All hyperparameters from `configs/base_config.yaml`
- 📈 **Per-epoch metrics**: Track learning curves over time
- 🧠 **Models**: Full model artifacts with versioning
- 📁 **Artifacts**: Config files, confusion matrices, model weights

## Quick Start

### 1. Install MLflow
```bash
pip install mlflow
```

Or update from requirements:
```bash
pip install -r requirements.txt
```

### 2. Enable MLflow (Already Configured)

MLflow is enabled by default in `configs/base_config.yaml`:
```yaml
mlflow:
  enabled: true
  experiment_name: "GNN_Vulnerability_Detection"
  tracking_uri: "outputs/mlruns"
  run_name_prefix: "gnn_vuln"
  log_models: true
  log_artifacts: true
```

### 3. Run Training (Auto-logs to MLflow)
```bash
python run_pipeline.py --step train
```

### 4. View Results in MLflow UI
```bash
python view_mlflow.py
```

Then open: **http://localhost:5000**

## What Gets Logged

### Hyperparameters (params)
```
Model Architecture:
- num_node_features, hidden_channels, num_classes
- dropout, gcn_layers, gat_heads

Training Config:
- learning_rate, weight_decay, batch_size
- num_epochs, patience, device

Dataset Config:
- max_safe_examples, max_nodes_per_graph
- test_split_size, validation_split_size, random_state
```

### Metrics (per epoch + final)
```
Training Metrics (per epoch):
- train_loss, train_accuracy
- val_loss, val_accuracy, val_precision, val_recall, val_f1
- epoch_time_seconds

Best Model Tracking:
- best_val_loss, best_epoch
- early_stopped_epoch (if early stopping triggered)

Final Test Metrics:
- test_loss, test_accuracy, test_precision, test_recall, test_f1
- total_training_time_minutes

Dataset Statistics:
- total_samples, train_samples, val_samples, test_samples
- train_safe_samples, train_vulnerable_samples
- class_imbalance_ratio
- class_weight_safe, class_weight_vulnerable
```

### Artifacts
```
- model/ (full PyTorch model for inference)
- model_weights/ (state_dict .pt file)
- config/base_config.yaml (exact config used for this run)
```

### Tags (for filtering)
```
- model_type: "GNN"
- architecture: "GCN+GAT"
- task: "vulnerability_detection"
- dataset: "github_advisories_codesearchnet"
```

## Using the MLflow UI

### Compare Experiments
1. Select multiple runs (checkbox on left)
2. Click **"Compare"** button
3. View side-by-side metrics, parameters, and charts

### View Training Curves
1. Click on a run
2. Go to **"Metrics"** tab
3. Select metrics to plot (e.g., `val_loss`, `train_accuracy`)
4. Use controls to zoom, download, or compare

### Load a Logged Model
```python
import mlflow
import mlflow.pytorch

# Load model from a specific run
model_uri = "runs:/<RUN_ID>/model"
loaded_model = mlflow.pytorch.load_model(model_uri)

# Or load latest production model
model_uri = "models:/VulnerabilityGNN/Production"
loaded_model = mlflow.pytorch.load_model(model_uri)
```

### Search and Filter Runs
```python
import mlflow

# Set tracking URI
mlflow.set_tracking_uri("outputs/mlruns")

# Search runs by metrics
runs = mlflow.search_runs(
    experiment_names=["GNN_Vulnerability_Detection"],
    filter_string="metrics.test_f1 > 0.95",
    order_by=["metrics.test_f1 DESC"]
)

print(runs[['run_id', 'metrics.test_f1', 'params.learning_rate']])
```

## Common Workflows

### Hyperparameter Tuning
1. Modify `configs/base_config.yaml` (e.g., change `learning_rate`)
2. Run training: `python run_pipeline.py --step train`
3. Repeat with different values
4. Compare in MLflow UI to find optimal settings

### Ablation Studies
Test impact of architectural changes:
```yaml
# Experiment 1: More GCN layers
model:
  gcn_layers: 6  # was 4

# Experiment 2: Higher dropout
model:
  dropout: 0.5  # was 0.3

# Experiment 3: More attention heads
model:
  gat_heads: 16  # was 8
```

Each run logs separately - compare results in UI.

### Model Registry
Promote best models to production:
```python
import mlflow

# Register a model from a run
run_id = "abc123..."
model_uri = f"runs:/{run_id}/model"

mlflow.register_model(
    model_uri=model_uri,
    name="VulnerabilityGNN"
)

# Transition to Production
client = mlflow.tracking.MlflowClient()
client.transition_model_version_stage(
    name="VulnerabilityGNN",
    version=1,
    stage="Production"
)
```

### Export Run Data
```python
import mlflow
import pandas as pd

# Get all runs
mlflow.set_tracking_uri("outputs/mlruns")
runs = mlflow.search_runs(
    experiment_names=["GNN_Vulnerability_Detection"]
)

# Save to CSV
runs.to_csv("outputs/results/mlflow_runs.csv", index=False)
```

## Directory Structure

```
outputs/
└── mlruns/                    # MLflow tracking data (gitignored)
    ├── 0/                     # Default experiment
    │   ├── meta.yaml
    │   └── <run_id>/          # Individual run data
    │       ├── artifacts/     # Logged artifacts
    │       ├── metrics/       # Metric files
    │       ├── params/        # Parameter files
    │       └── tags/          # Tags and metadata
    └── models/                # Registered models
```

## Configuration Options

### Disable MLflow
In `configs/base_config.yaml`:
```yaml
mlflow:
  enabled: false  # Set to false to disable tracking
```

### Change Tracking Location
```yaml
mlflow:
  tracking_uri: "file:///path/to/mlruns"  # Local path
  # OR
  tracking_uri: "http://localhost:5000"   # Remote server
```

### Disable Model Logging (Save Space)
```yaml
mlflow:
  log_models: false  # Only log metrics/params, not full models
```

### Custom Experiment Name
```yaml
mlflow:
  experiment_name: "GNN_Ablation_Study_Dec2024"
```

## Troubleshooting

### "ModuleNotFoundError: No module named 'mlflow'"
```bash
pip install mlflow
```

### MLflow UI shows "No experiments found"
- Make sure you've run training at least once
- Check that `outputs/mlruns` directory exists
- Verify tracking URI in config matches where UI is pointing

### Large disk usage
MLflow logs full models by default. To save space:
1. Set `log_models: false` in config
2. Delete old runs: `rm -rf outputs/mlruns/0/<old_run_id>`
3. Or keep only best runs, delete failed experiments

### Access MLflow from remote machine
```bash
python view_mlflow.py --host 0.0.0.0 --port 5000
```

Then access from: `http://<your-ip>:5000`

## Best Practices

### 1. Tag Your Experiments
Add custom tags in code:
```python
mlflow.set_tags({
    "researcher": "your_name",
    "purpose": "testing_new_features",
    "notes": "First run with edge features"
})
```

### 2. Log Additional Artifacts
```python
# Log confusion matrix
mlflow.log_artifact("outputs/results/confusion_matrix.png")

# Log custom analysis
mlflow.log_artifact("outputs/results/error_analysis.txt")
```

### 3. Document Runs
Use run descriptions:
```python
mlflow.set_tag("mlflow.note.content", """
This run tests the impact of increasing hidden channels 
from 128 to 256 on model performance.
""")
```

### 4. Archive Old Experiments
```bash
# Move old experiment data
mkdir outputs/mlruns_archive
mv outputs/mlruns/0/<old_run_ids> outputs/mlruns_archive/
```

## Integration with Git

MLflow complements Git version control:

**Git tracks**: Code, configs, documentation  
**MLflow tracks**: Metrics, models, artifacts, hyperparameters

**Workflow:**
```bash
# 1. Create feature branch
git checkout -b experiment/new-architecture

# 2. Modify code/config
vim configs/base_config.yaml

# 3. Run experiment (auto-logs to MLflow)
python run_pipeline.py --step train

# 4. If results good, commit code
git add configs/ src/
git commit -m "feat: New GNN architecture with residual connections"

# 5. Promote model in MLflow registry
# (Models are separate from code in MLflow)
```

## Resources

- **MLflow Docs**: https://mlflow.org/docs/latest/index.html
- **MLflow Tracking**: https://mlflow.org/docs/latest/tracking.html
- **MLflow Models**: https://mlflow.org/docs/latest/models.html
- **MLflow UI**: Access locally at http://localhost:5000

## Summary

✅ **Automatic tracking** - Every training run logs to MLflow  
✅ **Visual comparison** - Compare experiments in interactive UI  
✅ **Model versioning** - Track and deploy different model versions  
✅ **Reproducibility** - Full parameter/artifact logging ensures reproducibility  
✅ **Minimal overhead** - Negligible impact on training time  

**Next Steps:**
1. Run training: `python run_pipeline.py --step train`
2. Launch UI: `python view_mlflow.py`
3. Experiment with different hyperparameters
4. Compare results and find optimal configuration! 🚀
