# Data Pipeline: From GitHub Advisories to Training Dataset

## Overview

This document explains the complete data pipeline for extracting vulnerable Python code from the GitHub Security Advisory Database and combining it with safe code from CodeSearchNet to create a labeled training dataset.

## Pipeline Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│ 1. Filter Python Advisories                                         │
│    src/filter_python_advisories.py                                  │
│    Input:  data/advisory-database/**/*.json (28k+ JSON files)       │
│    Output: outputs/datasets/python_advisories.json                  │
│    Purpose: Extract PyPI ecosystem advisories                       │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│ 2. Preprocess & Extract Vulnerable Code                             │
│    scripts/00_preprocess_advisories.py                              │
│    Input:  outputs/datasets/python_advisories.json                  │
│    Output: outputs/datasets/processed_advisories_with_code.json     │
│    Purpose: Fetch commits from GitHub, extract vulnerable code      │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│ 3. Create Graph Dataset                                             │
│    scripts/01_create_dataset.py                                     │
│    Input:  processed_advisories_with_code.json + CodeSearchNet      │
│    Output: outputs/datasets/final_graph_dataset.pt              │
│    Purpose: Convert code to AST graphs, combine vulnerable + safe   │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│ 4. Train GNN Model                                                   │
│    src/train_model.py                                        │
│    Input:  final_graph_dataset.pt                                │
│    Output: outputs/models/trained_gnn_model.pt                   │
│    Purpose: Train GCN+GAT model with MLflow tracking                │
└─────────────────────────────────────────────────────────────────────┘
```

## Step-by-Step Guide

### Step 1: Filter Python Advisories

**Script:** `src/filter_python_advisories.py`

**What it does:**
- Recursively scans `data/advisory-database/advisories/github-reviewed/`
- Filters advisories where `ecosystem == "PyPI"` (Python packages)
- Saves metadata only: CVE ID, summary, severity, CWE IDs, references

**Output fields:**
```json
{
  "id": "GHSA-xxxx-yyyy-zzzz",
  "summary": "SQL injection in Django...",
  "severity": "HIGH",
  "cwe_ids": ["CWE-89"],
  "references": [
    {"url": "https://github.com/django/django/commit/abc123"}
  ]
}
```

**Run command:**
```bash
python src/filter_python_advisories.py
```

**Note:** This step does NOT extract actual code - only advisory metadata.

---

### Step 2: Extract Vulnerable Code from Commits

**Script:** `src/preprocess_advisories.py`

**What it does:**
1. Reads `python_advisories.json` from Step 1
2. Extracts GitHub commit/PR URLs from advisory references
3. Fetches commit data via GitHub API
4. Parses git diffs to extract vulnerable code (removed lines with `-` prefix)
5. Parses git diffs to extract fixed code (added lines with `+` prefix)
6. Filters Python files only (`.py` extension)
7. Saves processed advisories with actual code snippets

**Output fields:**
```json
{
  "advisory_id": "GHSA-xxxx-yyyy-zzzz",
  "summary": "SQL injection in Django...",
  "severity": "HIGH",
  "cwe_ids": ["CWE-89"],
  "vulnerable_code": "query = 'SELECT * FROM users WHERE id=' + user_id",
  "fixed_code": "query = 'SELECT * FROM users WHERE id=?'",
  "filename": "django/db/models/sql/compiler.py"
}
```

**GitHub API Rate Limits:**
- **Without token:** 60 requests/hour
- **With token:** 5000 requests/hour

**Setup GitHub Token (RECOMMENDED):**
```bash
# Windows Command Prompt
set GITHUB_PAT=ghp_your_token_here

# Windows PowerShell
$env:GITHUB_PAT="ghp_your_token_here"

# Linux/Mac
export GITHUB_PAT=ghp_your_token_here
```

**Run command:**
```bash
python src/preprocess_advisories.py
```

**Expected output:**
```
Starting advisory preprocessing pipeline...
Loading Python advisories from: outputs/datasets/python_advisories.json
Found 3,928 Python advisories

Filtering advisories with commit URLs: 100%|████| 3928/3928 [00:00<00:00]
Found 2,847 advisories with commit/PR URLs

Fetching commit data from GitHub: 100%|████| 2847/2847 [15:23<00:00]
✅ Successfully fetched: 2,623 commits
❌ Failed to fetch: 224 commits

Extracting vulnerable code from commits: 100%|████| 2623/2623 [00:12<00:00]
Found 1,897 advisories with Python vulnerable code

Summary:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total advisories processed: 3,928
Advisories with commit URLs: 2,847
Commits successfully fetched: 2,623
Advisories with Python code: 1,897
Output saved to: outputs/datasets/processed_advisories_with_code.json
```

**Key functions:**
- `find_commit_url()`: Extracts GitHub URLs from advisory references
- `fetch_commit_data()`: GitHub API fetching with retry logic and rate limiting
- `extract_code_from_patch()`: Parses git diffs to separate vulnerable/fixed code
- `extract_python_vulnerable_code()`: Filters Python files and validates code snippets

---

### Step 3: Create Graph Dataset

**Script:** `src/create_dataset.py`

**What it does:**
1. Loads vulnerable examples from `processed_advisories_with_code.json`
2. Streams safe examples from CodeSearchNet JSONL files
3. Converts Python code to Abstract Syntax Tree (AST) graphs
4. Converts AST to PyTorch Geometric `Data` objects
5. Saves combined dataset as `.pt` file

**Code-to-Graph Conversion:**
```
Python Code → ast.parse() → NetworkX DiGraph → PyTorch Geometric Data
```

**Node features:**
- AST node type (e.g., FunctionDef, Call, If, For) mapped to integer
- 11-dimensional padded feature vector

**Labels:**
- `label = 1`: Vulnerable code (from GitHub advisories)
- `label = 0`: Safe code (from CodeSearchNet)

**Run command:**
```bash
python src/create_dataset.py
```

**Expected output:**
```
Loading vulnerable examples from processed advisories...
Found 1,897 vulnerable code examples

Streaming safe examples from CodeSearchNet...
Processing CodeSearchNet files: 100%|████| 127/127 [03:45<00:00]
Loaded 200,000 safe code examples from CodeSearchNet

Converting to graphs: 100%|████| 201897/201897 [12:34<00:00]
Successfully converted: 196,423 graphs
Failed conversions: 5,474 (syntax errors/malformed code)

Dataset Statistics:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total examples: 196,423
Vulnerable (label=1): 1,823 (0.93%)
Safe (label=0): 194,600 (99.07%)
Class ratio: 1:107

Saved to: outputs/datasets/final_graph_dataset.pt
```

**Key functions:**
- `load_vulnerable_examples()`: Loads preprocessed advisories with actual code
- `stream_codesearchnet_examples()`: Streams safe code from JSONL files
- `code_to_pyg_graph()`: Converts Python code to PyTorch Geometric graph
- `ast_to_graph()`: Converts AST to NetworkX DiGraph

---

### Step 4: Train GNN Model

**Script:** `src/train_model.py`

**What it does:**
1. Loads processed dataset from `.pt` file
2. Splits data: 80% train, 10% validation, 10% test (stratified by label)
3. Calculates class weights for imbalanced data
4. Trains GNN model (4-layer GCN + GAT attention)
5. Tracks experiments with MLflow
6. Saves best model based on validation loss

**Run command:**
```bash
python src/train_model.py
```

See `docs/MLFLOW_GUIDE.md` for detailed training and experiment tracking information.

---

## Data Quality & Validation

### Vulnerable Code Extraction

**Challenges:**
1. **Not all advisories have commit references** - some only have descriptions
2. **GitHub API rate limits** - can take 30+ minutes to fetch 2,800 commits without token
3. **Empty or malformed patches** - some commits have no actual code changes
4. **Non-Python files** - advisories may reference configuration files, docs, etc.

**Solutions:**
- Filter advisories with commit URLs first (reduces API calls)
- Implement exponential backoff retry logic for API failures
- Validate extracted code is >20 characters (filters out empty snippets)
- Only extract from `.py` files in commits

### Safe Code Assumptions

**CodeSearchNet contains:**
- Open-source Python functions from GitHub repos
- ~2M+ Python functions in training set
- Assumed to be "safe" (no known vulnerabilities)

**Important caveat:** CodeSearchNet may contain vulnerable code that hasn't been discovered/reported yet. This is a limitation of the binary classification approach.

---

## Troubleshooting

### Problem: "No vulnerable examples found" after Step 2

**Diagnosis:** GitHub API rate limit exceeded or no token provided

**Solution:**
```bash
# Set GitHub token and re-run
set GITHUB_PAT=your_token_here
python scripts/00_preprocess_advisories.py
```

### Problem: "FileNotFoundError: processed_advisories_with_code.json"

**Diagnosis:** Skipped Step 2 preprocessing

**Solution:** Must run preprocessing before dataset creation:
```bash
python src/preprocess_advisories.py
python src/create_dataset.py
```

### Problem: High rate of failed graph conversions (>20%)

**Diagnosis:** Syntax errors in CodeSearchNet data or malformed code snippets

**Solution:** This is expected for ~5-10% of samples. If >20%, check:
- CodeSearchNet data integrity
- Python version compatibility (code may use Python 2 syntax)

### Problem: Very slow preprocessing (>1 hour)

**Diagnosis:** No GitHub token, hitting rate limits

**Solution:** Set `GITHUB_PAT` environment variable to increase from 60 to 5000 requests/hour.

---

## Configuration

All pipeline parameters are controlled by `configs/base_config.yaml`:

```yaml
data:
  # Path to processed advisories with actual code (created by Step 2)
  advisories_path: "outputs/datasets/processed_advisories_with_code.json"
  
  # Path to CodeSearchNet JSONL files (safe examples)
  codesearchnet_dir: "data/python/python/final/jsonl/train"
  
  # Output path for combined graph dataset
  processed_dataset_path: "outputs/datasets/final_graph_dataset.pt"

dataset:
  # Maximum number of safe examples to load from CodeSearchNet
  max_safe_examples: 200000
  
  # Maximum AST nodes per graph (truncates large functions)
  max_nodes_per_graph: 100
```

---

## Data Files Reference

| File | Size | Purpose | Created By |
|------|------|---------|------------|
| `python_advisories.json` | ~2MB | Advisory metadata only | `src/filter_python_advisories.py` |
| `processed_advisories_with_code.json` | ~15MB | Advisories + actual vulnerable code | `src/preprocess_advisories.py` |
| `final_graph_dataset.pt` | ~1.2GB | Graph dataset (vulnerable + safe) | `src/create_dataset.py` |
| `trained_gnn_model.pt` | ~5MB | Trained GNN weights | `src/train_model.py` |

---

## Next Steps

After completing the data pipeline:

1. **Train baseline model:**
   ```bash
   python src/train_model.py
   ```

2. **View experiments:**
   ```bash
   python view_mlflow.py
   ```

3. **Evaluate on test set:**
   ```bash
   python src/evaluate_model.py
   ```

For more details on training and evaluation, see:
- `docs/MLFLOW_GUIDE.md` - Experiment tracking
- `docs/00_EXECUTIVE_SUMMARY.md` - Project overview
- `docs/PROJECT_PROGRESS_2.md` - Development history
