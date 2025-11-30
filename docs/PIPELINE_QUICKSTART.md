# Pipeline Quick Start Guide

Complete workflow for training a vulnerability detection model from scratch.

## Prerequisites

✅ Python 3.9+ installed  
✅ GitHub Advisory Database cloned to `data/advisory-database/`  
✅ CodeSearchNet Python dataset downloaded to `data/python/python/final/jsonl/train/`  
✅ Dependencies installed: `pip install -r requirements.txt`

## One-Time Setup

### 1. Set GitHub Token (OPTIONAL but RECOMMENDED)

Increases API rate limit from 60 to 5000 requests/hour.

**Windows Command Prompt:**
```cmd
set GITHUB_PAT=ghp_your_token_here
```

**Windows PowerShell:**
```powershell
$env:GITHUB_PAT="ghp_your_token_here"
```

### 2. Configure Parameters (OPTIONAL)

Edit `configs/base_config.yaml` to adjust:
- Dataset size (`max_safe_examples: 200000`)
- Model architecture (`hidden_channels`, `gcn_layers`, etc.)
- Training parameters (`num_epochs`, `batch_size`, `learning_rate`)

## Complete Pipeline

### Step 0: Filter Python Advisories

Extract PyPI ecosystem advisories from GitHub Security Advisory Database.

```bash
python src/filter_python_advisories.py
```

**Time:** ~30 seconds  
**Output:** `outputs/datasets/python_advisories.json`  
**Size:** ~2MB (metadata for ~3,900 advisories)

---

### Step 1: Extract Vulnerable Code

Fetch commits from GitHub and extract actual vulnerable Python code from git diffs.

```bash
python src/preprocess_advisories.py
```

**Time:** 
- With token: ~15 minutes (5000 req/hour)
- Without token: ~3 hours (60 req/hour + automatic pauses)

**Output:** `outputs/datasets/processed_advisories_with_code.json`  
**Size:** ~15MB (~1,800 vulnerable code examples)

**Progress indicators:**
```
Filtering advisories with commit URLs: 100%|████| 3928/3928
Fetching commit data from GitHub: 100%|████| 2847/2847 [15:23<00:00]
Extracting vulnerable code: 100%|████| 2623/2623 [00:12<00:00]
```

---

### Step 2: Create Graph Dataset

Convert code to AST graphs and combine vulnerable + safe examples.

```bash
python src/create_dataset.py
```

**Time:** ~15 minutes  
**Output:** `outputs/datasets/final_graph_dataset.pt`  
**Size:** ~1.2GB (200k examples converted to graphs)

**Progress indicators:**
```
Processing CodeSearchNet files: 100%|████| 127/127 [03:45<00:00]
Converting to graphs: 100%|████| 201897/201897 [12:34<00:00]
```

---

### Step 3: Train Model

Train GNN with MLflow experiment tracking.

```bash
python src/train_model.py
```

**Time:** ~30 minutes (GPU) or ~2 hours (CPU)  
**Output:** `outputs/models/trained_gnn_model.pt`  
**Size:** ~5MB

**Progress indicators:**
```
Epoch 1/20: 100%|████| 3141/3141 [02:34<00:00] loss: 0.234, acc: 0.912
Validation: 100%|████| 349/349 [00:15<00:00] loss: 0.198, acc: 0.945
```

---

### Step 4: View Experiment Results

Launch MLflow UI to compare experiments.

```bash
python view_mlflow.py
```

Opens browser to `http://localhost:5000` with:
- All experiment runs and metrics
- Model versions and artifacts
- Hyperparameter comparisons
- Metric plots (loss, accuracy, F1, etc.)

---

## Quick Commands Reference

```bash
# Full pipeline from scratch
python src/filter_python_advisories.py
python src/preprocess_advisories.py
python src/create_dataset.py
python src/train_model.py
python view_mlflow.py

# Skip preprocessing (if already done)
python src/create_dataset.py
python src/train_model.py

# Only training (if dataset exists)
python src/train_model.py

# Evaluate saved model
python src/evaluate_model.py
```

---

## Expected Timeline

| Step | With GPU | With CPU | Notes |
|------|----------|----------|-------|
| Filter advisories | 30s | 30s | I/O bound |
| Extract vulnerable code | 15m | 15m | Network bound (with token) |
| Create dataset | 10m | 15m | CPU + I/O bound |
| Train model | 30m | 2h | GPU accelerated |
| **Total** | **~1 hour** | **~2.5 hours** | First run only |

**Subsequent training runs:** Skip preprocessing (Steps 0-2), train directly in ~30 minutes.

---

## Troubleshooting Quick Fixes

### "FileNotFoundError: processed_advisories_with_code.json"
**Fix:** Run preprocessing first: `python src/preprocess_advisories.py`

### "No vulnerable examples found"
**Fix:** Set GitHub token and re-run Step 1

### "CUDA out of memory"
**Fix:** Reduce `batch_size` in `configs/base_config.yaml` (try 32 → 16 → 8)

### Training appears frozen
**Fix:** Wait for tqdm progress bars to update (may take 10-30 seconds per epoch start)

### "GitHub API rate limit exceeded"
**Fix:** Wait 1 hour or set `GITHUB_PAT` environment variable

---

## What Each Step Does

| Step | Input | Output | Purpose |
|------|-------|--------|---------|
| 0 | Advisory DB JSON files | `python_advisories.json` | Filter PyPI advisories |
| 1 | Advisory metadata | `processed_advisories_with_code.json` | Extract vulnerable code from commits |
| 2 | Vulnerable + CodeSearchNet | `final_graph_dataset.pt` | Convert code to graphs |
| 3 | Graph dataset | `trained_gnn_model.pt` | Train GNN classifier |

---

## Data File Sizes

```
outputs/
├── datasets/
│   ├── python_advisories.json              (~2MB)
│   ├── processed_advisories_with_code.json (~15MB)
│   └── final_graph_dataset.pt              (~1.2GB)
└── models/
│   └── trained_gnn_model.pt                (~5MB)
└── mlruns/
    └── <experiment_id>/                     (~50MB per run)
```

---

## Configuration Presets

### Quick Experiment (Fast Training)

Edit `configs/base_config.yaml`:
```yaml
dataset:
  max_safe_examples: 10000  # Reduced from 200k
training:
  num_epochs: 5             # Reduced from 20
  batch_size: 128           # Increased for speed
```

**Training time:** ~5 minutes

### Full Dataset (Best Performance)

Use defaults in `configs/base_config.yaml`:
```yaml
dataset:
  max_safe_examples: 200000
training:
  num_epochs: 20
  batch_size: 64
```

**Training time:** ~30 minutes (GPU) or ~2 hours (CPU)

---

## Next Steps After First Run

1. **Compare experiments:** `python view_mlflow.py`
2. **Adjust hyperparameters:** Edit `configs/base_config.yaml`
3. **Retrain:** `python src/train_model.py` (reuses existing dataset)
4. **Evaluate:** `python src/evaluate_model.py`

For detailed documentation, see:
- `docs/DATA_PIPELINE.md` - Complete pipeline explanation
- `docs/MLFLOW_GUIDE.md` - Experiment tracking guide
- `README.md` - Project overview
