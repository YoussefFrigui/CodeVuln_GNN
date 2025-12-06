# Quick Reference: Before & After

## BEFORE (Messy Root Directory)
```
GNN_project/
├── 00_EXECUTIVE_SUMMARY.md              ❌ Doc in root
├── 01_CODE_AND_ARCHITECTURE_REVIEW.md   ❌ Doc in root
├── 02_MLOPS_AND_REPRODUCIBILITY_AUDIT.md ❌ Doc in root
├── 03_MODEL_AND_EVALUATION_CRITIQUE.md  ❌ Doc in root
├── 04_DOCUMENTATION_AND_ONBOARDING.md   ❌ Doc in root
├── PROJECT_PROGRESS.md                  ❌ Doc in root
├── PROJECT_PROGRESS_2.md                ❌ Doc in root
├── GUIDE.md                             ❌ Doc in root
├── proposition.md                       ❌ Doc in root
├── steps_to_follow.md                   ❌ Doc in root
├── confusion_matrix.png                 ❌ Result in root
├── commit_data_results.json             ❌ Result in root
├── data_loaders.pt                      ❌ Dataset in root
├── data_splits.pt                       ❌ Dataset in root
├── expanded_labeled_dataset.json        ❌ Dataset in root
├── extracted_full_functions.json        ❌ Dataset in root
├── extracted_snippets.json              ❌ Dataset in root
├── labeled_dataset.json                 ❌ Dataset in root
├── massive_codesearchnet_dataset.pt     ❌ Dataset in root
├── processed_graphs.pt                  ❌ Dataset in root
├── python_advisories.json               ❌ Dataset in root
├── python_advisories_with_commits.json  ❌ Dataset in root
├── massive_vulnerability_gnn_model.pt   ❌ Model in root
├── vulnerability_gnn_model.pt           ❌ Model in root
├── configs/                             ✅ Good
├── data/                                ✅ Good
├── scripts/                             ✅ Good
├── src/                                 ✅ Good
├── README.md                            ✅ Good
├── requirements.txt                     ✅ Good
└── run_pipeline.py                      ✅ Good
```

**Problems:**
- 20+ files in root directory
- Mixed documentation, datasets, models, and results
- Hard to find what you need
- Confusing for new contributors
- Poor Git hygiene

---

## AFTER (Clean & Organized)
```
GNN_project/
├── configs/                             ✅ Configuration
│   └── base_config.yaml
├── data/                                ✅ Raw input data
│   ├── advisory-database/
│   └── python/
├── docs/                                ✅ All documentation
│   ├── 00_EXECUTIVE_SUMMARY.md
│   ├── 01_CODE_AND_ARCHITECTURE_REVIEW.md
│   ├── 02_MLOPS_AND_REPRODUCIBILITY_AUDIT.md
│   ├── 03_MODEL_AND_EVALUATION_CRITIQUE.md
│   ├── 04_DOCUMENTATION_AND_ONBOARDING.md
│   ├── PROJECT_PROGRESS.md
│   ├── PROJECT_PROGRESS_2.md
│   ├── PROJECT_STRUCTURE.md
│   ├── GUIDE.md
│   ├── proposition.md
│   └── steps_to_follow.md
├── outputs/                             ✅ All generated files
│   ├── datasets/                        ✅ Processed data
│   │   ├── massive_codesearchnet_dataset.pt
│   │   ├── processed_graphs.pt
│   │   ├── data_splits.pt
│   │   ├── data_loaders.pt
│   │   ├── python_advisories.json
│   │   ├── python_advisories_with_commits.json
│   │   ├── expanded_labeled_dataset.json
│   │   ├── extracted_full_functions.json
│   │   ├── extracted_snippets.json
│   │   └── labeled_dataset.json
│   ├── models/                          ✅ Trained models
│   │   ├── massive_vulnerability_gnn_model.pt
│   │   └── vulnerability_gnn_model.pt
│   └── results/                         ✅ Evaluation outputs
│       ├── confusion_matrix.png
│       └── commit_data_results.json
├── scripts/                             ✅ Main scripts
│   ├── 01_create_dataset.py
│   └── 02_train_model.py
├── src/                                 ✅ Source modules
│   ├── data_processing/
│   ├── modeling/
│   └── [other utility scripts]
├── .gitignore                           ✅ Essential files
├── README.md
├── requirements.txt
├── run_pipeline.py
└── REORGANIZATION_SUMMARY.md            ✅ This change log
```

**Benefits:**
- ✅ Clean root (only 6 essential files)
- ✅ Logical grouping by purpose
- ✅ Easy to navigate
- ✅ Clear for new contributors
- ✅ Better Git management
- ✅ Scalable structure

---

## Quick File Finder

Need to find something? Use this quick reference:

| What You Need | Where to Look |
|---------------|---------------|
| Documentation & guides | `docs/` |
| Configuration settings | `configs/base_config.yaml` |
| Raw advisory data | `data/advisory-database/` |
| CodeSearchNet data | `data/python/` |
| Processed datasets | `outputs/datasets/` |
| Trained models | `outputs/models/` |
| Evaluation results | `outputs/results/` |
| Main executable scripts | `scripts/` |
| Source code modules | `src/` |
| Pipeline runner | `run_pipeline.py` (root) |
| Setup instructions | `README.md` (root) |
| Dependencies | `requirements.txt` (root) |

---

## Common Tasks

### I want to...

**Read project documentation**
→ Go to `docs/` directory

**Change model hyperparameters**
→ Edit `configs/base_config.yaml`

**Find a trained model**
→ Check `outputs/models/`

**Access processed datasets**
→ Check `outputs/datasets/`

**View evaluation results**
→ Check `outputs/results/`

**Run the full pipeline**
→ `python run_pipeline.py --step all`

**Train a new model**
→ `python run_pipeline.py --step train`

**Create new dataset**
→ `python run_pipeline.py --step preprocess`

---

## Git Workflow

### What's Tracked
```
✅ configs/       (Configuration files)
✅ docs/          (Documentation)
✅ scripts/       (Executable scripts)
✅ src/           (Source code)
✅ .gitignore
✅ README.md
✅ requirements.txt
✅ run_pipeline.py
```

### What's Ignored
```
❌ data/          (Raw data - too large)
❌ outputs/       (Generated files - reproducible)
❌ __pycache__/   (Python bytecode)
```

### Typical Commit
```bash
# Stage code changes
git add src/ scripts/ configs/

# Stage documentation
git add docs/ README.md

# Commit with descriptive message
git commit -m "feat: Add new graph features to AST conversion"

# Push
git push
```

---

## Path Cheat Sheet

### In Python Code
```python
# ✅ GOOD - Use config
import yaml
with open('configs/base_config.yaml', 'r') as f:
    config = yaml.safe_load(f)
dataset_path = config['data']['processed_dataset_path']
# Result: 'outputs/datasets/massive_codesearchnet_dataset.pt'

# ❌ BAD - Hardcoded
dataset_path = 'massive_codesearchnet_dataset.pt'
```

### In Config File
```yaml
# All paths relative to project root
data:
  advisories_path: "outputs/datasets/python_advisories.json"
  processed_dataset_path: "outputs/datasets/massive_codesearchnet_dataset.pt"

output:
  model_save_path: "outputs/models/massive_vulnerability_gnn_model.pt"
```

---

## Summary

| Aspect | Before | After |
|--------|--------|-------|
| Root files | 26 | 6 |
| Organization | ❌ Poor | ✅ Excellent |
| Git cleanliness | ❌ Mixed tracked/untracked | ✅ Clear separation |
| New contributor experience | ❌ Confusing | ✅ Intuitive |
| Maintainability | ❌ Difficult | ✅ Easy |
| Scalability | ❌ Limited | ✅ High |

**Result: Clean, organized, professional project structure! 🎉**
