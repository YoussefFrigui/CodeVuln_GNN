# MLflow Quick Reference Card

## 🚀 Getting Started (3 Steps)

```bash
# 1. Install MLflow
pip install mlflow

# 2. Run training (auto-tracks to MLflow)
python run_pipeline.py --step train

# 3. View results
python view_mlflow.py
```

**Browser**: http://localhost:5000

---

## 📊 What's Tracked Automatically

| Category | Metrics Logged |
|----------|----------------|
| **Training** | train_loss, train_accuracy (per epoch) |
| **Validation** | val_loss, val_accuracy, val_precision, val_recall, val_f1 (per epoch) |
| **Test** | test_loss, test_accuracy, test_precision, test_recall, test_f1 (final) |
| **Best Model** | best_val_loss, best_epoch, early_stopped_epoch |
| **Performance** | epoch_time_seconds, total_training_time_minutes |
| **Dataset Stats** | total_samples, train/val/test split sizes, class imbalance ratio, class weights |

---

## ⚙️ Configuration (configs/base_config.yaml)

```yaml
mlflow:
  enabled: true                     # Toggle on/off
  experiment_name: "GNN_Vuln"       # Group related runs
  tracking_uri: "outputs/mlruns"    # Where data is stored
  run_name_prefix: "gnn_vuln"       # Run naming
  log_models: true                  # Log full models
  log_artifacts: true               # Log configs/matrices
```

---

## 🔍 Common UI Tasks

### Compare Experiments
1. ✅ Select multiple runs (checkbox)
2. Click **"Compare"** button
3. View side-by-side metrics and params

### View Training Curves
1. Click a run
2. **"Metrics"** tab
3. Select metrics to plot
4. Zoom/download/compare

### Find Best Model
1. Click column header to sort (e.g., "test_f1")
2. Top row = best model
3. Click for details

---

## 💻 Programmatic Access

### Load a Model
```python
import mlflow.pytorch

# From specific run
model = mlflow.pytorch.load_model("runs:/RUN_ID/model")

# From model registry
model = mlflow.pytorch.load_model("models:/VulnerabilityGNN/Production")
```

### Search Runs
```python
import mlflow

mlflow.set_tracking_uri("outputs/mlruns")
runs = mlflow.search_runs(
    experiment_names=["GNN_Vulnerability_Detection"],
    filter_string="metrics.test_f1 > 0.95",
    order_by=["metrics.test_f1 DESC"]
)
```

### Export to CSV
```python
runs = mlflow.search_runs()
runs.to_csv("experiment_results.csv")
```

---

## 🎯 Experiment Workflows

### Hyperparameter Tuning
```bash
# 1. Edit configs/base_config.yaml (change learning_rate)
# 2. Run: python run_pipeline.py --step train
# 3. Repeat with different values
# 4. Compare in MLflow UI
```

### Ablation Study
Test architectural changes:
- Change `gcn_layers: 4 → 6`
- Run training
- Compare test_f1 in UI

### Model Selection
1. Sort by test_f1 in UI
2. Note best run_id
3. Promote to production in Model Registry

---

## 🗂️ File Structure

```
outputs/
└── mlruns/                 # MLflow tracking (gitignored)
    └── 0/                  # Experiment ID
        ├── abc123/         # Run ID
        │   ├── artifacts/  # Models, configs, matrices
        │   ├── metrics/    # Metric history
        │   ├── params/     # Hyperparameters
        │   └── tags/       # Metadata
        └── meta.yaml       # Experiment info
```

---

## 🛠️ Troubleshooting

| Problem | Solution |
|---------|----------|
| "No module named mlflow" | `pip install mlflow` |
| UI shows no experiments | Run training first, check `outputs/mlruns` exists |
| Large disk usage | Set `log_models: false` or delete old runs |
| Can't access UI remotely | Use `--host 0.0.0.0` when launching |

---

## 📋 Quick Commands

```bash
# View MLflow UI
python view_mlflow.py

# Install dependencies
pip install -r requirements.txt

# Run full pipeline with MLflow tracking
python run_pipeline.py --step all

# Disable MLflow temporarily
# Set mlflow.enabled: false in config

# Clean old runs (careful!)
rm -rf outputs/mlruns/0/OLD_RUN_ID
```

---

## 🎓 Learn More

- **Full Guide**: `docs/MLFLOW_GUIDE.md`
- **MLflow Docs**: https://mlflow.org/docs/latest/
- **Tracking**: https://mlflow.org/docs/latest/tracking.html
- **Models**: https://mlflow.org/docs/latest/models.html

---

## 💡 Pro Tips

1. **Tag your experiments**: Add custom tags for easy filtering
2. **Compare baselines**: Always keep a baseline run for comparison
3. **Export results**: Use CSV export for papers/reports
4. **Archive old runs**: Move to `mlruns_archive/` folder
5. **Document runs**: Use `mlflow.note.content` tag for notes

---

**🎉 That's it! Happy experimenting!**
