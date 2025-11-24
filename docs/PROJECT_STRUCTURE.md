# Project Structure Guide

## Overview

This document explains the organization of the GNN Vulnerability Detection project, detailing the purpose of each directory and key files.

## Directory Structure

```
GNN_project/
│
├── configs/                    # Configuration files
│   └── base_config.yaml       # Main configuration (paths, hyperparameters)
│
├── data/                       # Raw input data (not tracked in Git)
│   ├── advisory-database/     # GitHub Security Advisory Database
│   └── python/                # CodeSearchNet Python dataset
│
├── docs/                       # Project documentation
│   ├── 00_EXECUTIVE_SUMMARY.md
│   ├── 01_CODE_AND_ARCHITECTURE_REVIEW.md
│   ├── 02_MLOPS_AND_REPRODUCIBILITY_AUDIT.md
│   ├── 03_MODEL_AND_EVALUATION_CRITIQUE.md
│   ├── 04_DOCUMENTATION_AND_ONBOARDING.md
│   ├── PROJECT_PROGRESS.md
│   ├── PROJECT_PROGRESS_2.md
│   ├── GUIDE.md
│   ├── proposition.md
│   └── steps_to_follow.md
│
├── outputs/                    # All generated outputs (not tracked in Git)
│   ├── datasets/              # Processed datasets
│   │   ├── final_graph_dataset.pt
│   │   ├── processed_graphs.pt
│   │   ├── data_splits.pt
│   │   ├── python_advisories.json
│   │   ├── expanded_labeled_dataset.json
│   │   ├── extracted_full_functions.json
│   │   ├── extracted_snippets.json
│   │   ├── processed_advisories_with_code.json
│   │   ├── python_advisories.json
│   │   └── data_splits.pt
│   │
│   ├── models/                # Trained model weights
│   │   └── trained_gnn_model.pt
│   │
│   └── results/               # Evaluation results and visualizations
│       ├── confusion_matrix.png
│       └── commit_data_results.json
│
├── scripts/                    # Main executable scripts
│   ├── 01_create_dataset.py   # Dataset creation from raw data
│   └── 02_train_model.py      # Model training and evaluation
│
├── src/                        # Source code modules
│   ├── data_processing/
│   │   └── graph_utils.py     # AST to graph conversion utilities
│   │
│   ├── modeling/
│   │   └── model.py           # GNN model architecture
│   │
│   ├── training/              # Training utilities (if any)
│   │
│   ├── create_labeled_dataset.py
│   ├── evaluate_model.py
│   ├── expand_dataset.py
│   ├── extract_commit_urls.py
│   ├── extract_full_functions.py
│   ├── extract_snippets.py
│   ├── fetch_commit_data.py
│   ├── filter_python_advisories.py
│   └── train_gnn.py
│
├── .github/
│   └── copilot-instructions.md  # AI assistant guidelines
│
├── .gitignore                  # Git ignore rules
├── README.md                   # Project overview and setup guide
├── requirements.txt            # Python dependencies
└── run_pipeline.py            # Main pipeline orchestrator

```

## Key Directories Explained

### `/configs`
Contains all configuration files. The `base_config.yaml` is the single source of truth for:
- File paths (input/output)
- Dataset parameters (max samples, graph sizes)
- Model architecture (layers, dimensions, dropout)
- Training hyperparameters (learning rate, batch size, epochs)

**Never hardcode these values in scripts!** Always read from config.

### `/data`
Stores raw, unprocessed data. This directory is **not tracked in Git** (see `.gitignore`).

**Setup Requirements:**
1. Clone GitHub Advisory Database:
   ```bash
   cd data
   git clone https://github.com/github/advisory-database.git
   ```

2. Download CodeSearchNet Python dataset to:
   ```
   data/python/python/final/jsonl/train/
   ```

### `/docs`
All project documentation, including:
- Progress reports (`PROJECT_PROGRESS*.md`)
- Code reviews and audits (`0*_*.md`)
- User guides (`GUIDE.md`, `steps_to_follow.md`)

**When to update:**
- After completing significant milestones
- When making architectural changes
- To document experimental findings

### `/outputs`
All generated files from the pipeline. Organized into three subdirectories:

#### `/outputs/datasets`
Processed datasets in various stages:
- `python_advisories.json` - Filtered advisory data
- `final_graph_dataset.pt` - Full graph dataset
- `processed_advisories_with_code.json` - Vulnerable code from commits
- `data_splits.pt` - Train/val/test splits

#### `/outputs/models`
Trained model checkpoints:
- `trained_gnn_model.pt` - Current trained model

#### `/outputs/results`
Evaluation outputs and visualizations:
- `confusion_matrix.png` - Test set confusion matrix
- `commit_data_results.json` - Fetched commit data

**Note:** The entire `/outputs` directory is gitignored. Use Git LFS or document download instructions if sharing models.

### `/scripts`
Production-ready executable scripts called by `run_pipeline.py`:

- **01_create_dataset.py**: Loads vulnerable and safe code, converts to graphs, saves dataset
- **02_train_model.py**: Trains model with early stopping, evaluates on test set, saves weights

These scripts are config-driven and should work standalone after proper setup.

### `/src`
Source code modules and utilities:

- **data_processing/**: Graph conversion, AST parsing
- **modeling/**: GNN architecture definitions
- Other standalone scripts for data extraction and preprocessing

## File Naming Conventions

- `massive_*` - Files using the full 200k+ dataset
- `*_advisories.json` - Human-readable advisory data
- `*.pt` - PyTorch serialized objects (models, datasets)
- `*_splits.pt` - Train/validation/test data splits
- `confusion_matrix.png` - Evaluation visualizations

## Common Workflows

### Starting a New Experiment
1. Update `configs/base_config.yaml` with new parameters
2. Run pipeline: `python run_pipeline.py --step all`
3. Document results in `docs/PROJECT_PROGRESS_2.md`

### Changing Model Architecture
1. Edit `src/modeling/model.py`
2. Update config model section if needed
3. Run: `python run_pipeline.py --step train` (skips data prep)

### Adding New Features to Graphs
1. Update `src/data_processing/graph_utils.py`
2. Adjust `num_node_features` in config
3. Regenerate dataset: `python run_pipeline.py --step preprocess`
4. Retrain: `python run_pipeline.py --step train`

## Path Management

All paths in code should:
1. Read from `configs/base_config.yaml` when possible
2. Use relative paths from project root
3. Be OS-agnostic (use `os.path.join()`)

**Example:**
```python
# Good
with open('configs/base_config.yaml', 'r') as f:
    config = yaml.safe_load(f)
model_path = config['output']['model_save_path']

# Bad (don't do this!)
model_path = 'trained_gnn_model.pt'  # Hardcoded, missing outputs/models/ prefix!
```

## Cleanup and Maintenance

### Removing Old Outputs
```bash
# Windows
rmdir /s /q outputs\datasets
rmdir /s /q outputs\models
rmdir /s /q outputs\results

# Linux/Mac
rm -rf outputs/datasets outputs/models outputs/results
```

Then regenerate as needed with `run_pipeline.py`.

### Checking Disk Space
Dataset files can be large (200k+ graphs = several GB):
- `final_graph_dataset.pt`: ~1.2 GB
- `trained_gnn_model.pt`: ~5 MB

Monitor disk usage regularly if experimenting frequently.

## Git Best Practices

### What to Commit
- All code files (`.py`)
- Configuration files (`configs/*.yaml`)
- Documentation (`docs/*.md`, `README.md`)
- Requirements (`requirements.txt`)

### What NOT to Commit
- `/data` directory (raw data)
- `/outputs` directory (generated files)
- `__pycache__` directories
- `.pt`, `.json`, `.png` files in root (moved to `/outputs`)

### Example Commit Workflow
```bash
git add src/ scripts/ configs/ docs/ README.md
git commit -m "Refactor: Organize project structure into docs/ and outputs/"
git push
```

## Troubleshooting

### "File not found" errors after reorganization
Check that:
1. Files were moved to correct subdirectories
2. All hardcoded paths updated to new structure
3. Config file points to new locations

### Pipeline fails at a specific step
1. Check required files exist in `/outputs/datasets` or `/outputs/models`
2. Run earlier steps: `python run_pipeline.py --step preprocess`
3. Verify data integrity (file sizes, not corrupted)

### Need to revert to old structure
Files are moved, not deleted. To revert:
```bash
move outputs\datasets\*.pt .
move outputs\datasets\*.json .
move outputs\models\*.pt .
move docs\*.md .
```

Then update paths in config and code files.

## Summary

This reorganization achieves:
- ✅ Clean root directory (only essential files)
- ✅ Logical grouping (docs, outputs, source)
- ✅ Easier navigation for new contributors
- ✅ Better Git hygiene (outputs properly ignored)
- ✅ Scalable structure for future additions

All scripts and config updated to reflect new paths. No functionality changes, just organization.
