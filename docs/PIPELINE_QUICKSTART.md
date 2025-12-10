# Pipeline Quick Start Guide

Complete workflow for training a vulnerability detection model from scratch.

## Prerequisites

✅ Python 3.9+ installed  
✅ GitHub Advisory Database cloned to `data/advisory-database/`  
✅ CodeSearchNet Python dataset downloaded to `data/python/python/final/jsonl/train/`  
✅ Dependencies installed: `pip install -r requirements.txt`

## Quick Start (If Data Already Prepared)

```bash
# Run entire pipeline
python run_pipeline.py --step all

# Or run individual steps
python run_pipeline.py --step preprocess   # Create dataset
python run_pipeline.py --step train        # Train model
python run_pipeline.py --step evaluate     # Evaluate model
```

## One-Time Setup

### 1. Set GitHub Token (RECOMMENDED)

Increases API rate limit from 60 to 5000 requests/hour.

**Windows Command Prompt:**
```cmd
set GITHUB_TOKEN=ghp_your_token_here
```

**Windows PowerShell:**
```powershell
$env:GITHUB_TOKEN="ghp_your_token_here"
```

### 2. Configure Parameters

Edit `configs/base_config.yaml` to adjust:
- Dataset size (`max_safe_examples: 200000`)
- Model architecture (`hidden_channels`, `gcn_layers`, etc.)
- Training parameters (`num_epochs`, `batch_size`, `learning_rate`)

## Full Data Pipeline (First Time Only)

### Step 0: Filter Python Advisories

```bash
python src/filter_python_advisories.py
```

**Time:** ~30 seconds  
**Output:** `outputs/datasets/python_advisories.json`

---

### Step 1: Fetch Full Files from GitHub

This fetches complete Python files (not just diffs) from GitHub API:

```bash
python src/fetch_full_files.py

# Resume if interrupted
python src/fetch_full_files.py --resume
```

**Time:** 2-8 hours (depending on rate limits)  
**Output:** `outputs/datasets/processed_advisories_full_files.json`

💡 This is a long-running process - run separately from training!

---

### Step 2: Extract Code from Descriptions

For advisories without commit URLs:

```bash
python src/extract_description_code.py
```

**Time:** ~1 minute  
**Output:** `outputs/datasets/description_extracted_code.json`

---

### Step 3: Merge All Data Sources

Combine all sources with deduplication:

```bash
python src/merge_all_sources.py
```

**Time:** ~10 seconds  
**Output:** `outputs/datasets/merged_vulnerabilities.json`

---

### Step 4: Create Dataset & Train

Now use the main pipeline:

```bash
python run_pipeline.py --step all
```

This:
1. Creates graph dataset from merged vulnerabilities + CodeSearchNet
2. Trains GNN model
3. Evaluates and saves results

---

## Quick Commands Reference

```bash
# === DATA ACQUISITION (run once) ===
python src/filter_python_advisories.py       # Filter advisories
python src/fetch_full_files.py               # Fetch from GitHub (hours)
python src/extract_description_code.py       # Extract from descriptions
python src/merge_all_sources.py              # Combine all sources

# === MODEL DEVELOPMENT (run often) ===
python run_pipeline.py --step all            # Full pipeline
python run_pipeline.py --step train          # Training only
python run_pipeline.py --step evaluate       # Evaluation only

# === UTILITIES ===
python view_mlflow.py                        # View experiment tracking
```

---

## Expected Timeline

| Step | Duration | Notes |
|------|----------|-------|
| Filter advisories | 30s | One-time |
| Fetch full files | 2-8h | One-time, has resume |
| Extract descriptions | 1m | One-time |
| Merge sources | 10s | One-time |
| Create dataset | 10-15m | After any data change |
| Train model | 30m GPU / 2h CPU | Each experiment |
| **Total first run** | **3-9 hours** | Mostly fetching |
| **Subsequent runs** | **30-45 minutes** | Training only |

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
