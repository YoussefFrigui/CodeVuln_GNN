# Complete Pipeline Workflow

## Visual Overview

```
┌────────────────────────────────────────────────────────────────────────────┐
│                                                                            │
│                    GNN VULNERABILITY DETECTION PIPELINE                    │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘


STEP 0: FILTER ADVISORIES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📁 data/advisory-database/advisories/github-reviewed/**/*.json
                                │
                                │ (Scan ~28k JSON files)
                                ▼
                    src/filter_python_advisories.py
                                │
                                │ (Filter: ecosystem == "PyPI")
                                ▼
📄 outputs/datasets/python_advisories.json (~3,900 advisories)
   {
     "id": "GHSA-xxxx-yyyy-zzzz",
     "summary": "SQL injection...",
     "severity": "HIGH",
     "references": [{"url": "https://github.com/..."}]
   }


STEP 1: EXTRACT VULNERABLE CODE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📄 outputs/datasets/python_advisories.json
                                │
                                │ (Extract commit URLs)
                                ▼
                scripts/00_preprocess_advisories.py
                                │
                                │ ┌──────────────────────┐
                                │ │ GitHub API Fetching  │
                                │ │ • Rate limiting      │
                                │ │ • Retry logic        │
                                │ │ • Progress tracking  │
                                │ └──────────────────────┘
                                ▼
                        Commit Data (JSON)
                                │
                                │ (Parse git diffs)
                                │ - Lines = vulnerable code
                                │ + Lines = fixed code
                                ▼
📄 outputs/datasets/processed_advisories_with_code.json (~1,800 examples)
   {
     "advisory_id": "GHSA-xxxx-yyyy-zzzz",
     "vulnerable_code": "query = 'SELECT * FROM...'",
     "fixed_code": "query = 'SELECT * FROM WHERE id=?'",
     "filename": "models/sql.py"
   }


STEP 2: CREATE GRAPH DATASET
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

┌──────────────────────────────────────┐  ┌──────────────────────────────────┐
│ VULNERABLE CODE                      │  │ SAFE CODE                        │
│                                      │  │                                  │
│ processed_advisories_with_code.json  │  │ data/python/.../train/*.jsonl    │
│ (~1,800 examples)                    │  │ (CodeSearchNet: 200k examples)   │
└──────────────────────────────────────┘  └──────────────────────────────────┘
                    │                                    │
                    └────────────────┬───────────────────┘
                                     │
                                     ▼
                     src/create_dataset.py
                                     │
                                     │ ┌─────────────────────┐
                                     │ │ Code → Graph        │
                                     │ │                     │
                                     │ │ 1. ast.parse()      │
                                     │ │ 2. AST → NetworkX   │
                                     │ │ 3. NetworkX → PyG   │
                                     │ └─────────────────────┘
                                     ▼
📦 outputs/datasets/final_graph_dataset.pt
   PyTorch Geometric Dataset (200k+ graphs)
   
   Graph Structure:
   • Nodes: AST elements (FunctionDef, Call, If, etc.)
   • Edges: Parent-child relationships
   • Features: 11-dim node type embeddings
   • Labels: 0 (safe) or 1 (vulnerable)


STEP 3: TRAIN GNN MODEL
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📦 final_graph_dataset.pt
                    │
                    │ (Load & split: 80/10/10)
                    ▼
        scripts/02_train_model.py
                    │
                    │ ┌────────────────────────────┐
                    │ │ GNN Architecture           │
                    │ │ • 4x GCN layers            │
                    │ │ • GAT attention layer      │
                    │ │ • Global mean pooling      │
                    │ │ • MLP classifier           │
                    │ └────────────────────────────┘
                    │
                    │ ┌────────────────────────────┐
                    │ │ Training Loop              │
                    │ │ • Weighted cross-entropy   │
                    │ │ • Early stopping           │
                    │ │ • MLflow tracking          │
                    │ └────────────────────────────┘
                    │
                    ├──────────────────────────────────────┐
                    │                                      │
                    ▼                                      ▼
🧠 outputs/models/                              📊 outputs/mlruns/
   trained_gnn_model.pt                            <experiment_id>/
   (Trained model weights)                         ├── metrics/
                                                   ├── params/
                                                   ├── artifacts/
                                                   └── model/


STEP 4: EVALUATION & TRACKING
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📊 outputs/mlruns/
        │
        │ (Launch UI)
        ▼
python view_mlflow.py
        │
        ▼
┌────────────────────────────────────────────────────────────────────┐
│ MLflow UI (http://localhost:5000)                                 │
│                                                                    │
│ Experiments:                                                       │
│ ├── Run 1: baseline (accuracy: 0.992, F1: 0.843)                  │
│ ├── Run 2: larger_hidden (accuracy: 0.994, F1: 0.867)             │
│ └── Run 3: more_layers (accuracy: 0.995, F1: 0.891)               │
│                                                                    │
│ Metrics Charts:                                                    │
│ • Training/Validation Loss                                         │
│ • Accuracy, Precision, Recall, F1                                  │
│ • Per-class performance                                            │
│                                                                    │
│ Model Registry:                                                    │
│ └── VulnerabilityGNN (version 3) - Production                     │
└────────────────────────────────────────────────────────────────────┘
```

## Data Flow Summary

```
Raw JSON Files → Python Advisories → Vulnerable Code → Graph Dataset → Trained Model
  (28k files)      (3.9k advisories)    (1.8k examples)   (200k graphs)    (GNN)
     ~500MB            ~2MB                 ~15MB            ~1.2GB         ~5MB
```

## Key Metrics at Each Stage

| Stage | Input Count | Output Count | Filtering Reason |
|-------|-------------|--------------|------------------|
| Filter Advisories | 28,000 | 3,900 | Only PyPI ecosystem |
| Extract Vulnerable Code | 3,900 | 1,800 | Only with commit URLs + Python code |
| Create Graphs | 201,800 | 196,400 | Syntax errors, malformed code |
| Training | 196,400 | 196,400 | No filtering (all used) |

## Class Distribution

```
Vulnerable Examples (label=1):    1,800 (0.92%)  ████
Safe Examples (label=0):        194,600 (99.08%) ████████████████████████████████

Class Imbalance Ratio: 1:108

Solution: Weighted Cross-Entropy Loss
  • Safe class weight:       ~0.5
  • Vulnerable class weight: ~54.0
```

## Processing Time Breakdown

```
┌─────────────────────────┬───────────┬──────────────────────────┐
│ Step                    │ Duration  │ Bottleneck              │
├─────────────────────────┼───────────┼──────────────────────────┤
│ Filter advisories       │ 30 sec    │ I/O (file scanning)     │
│ Extract vulnerable code │ 15 min    │ Network (GitHub API)    │
│ Create dataset          │ 15 min    │ CPU (AST parsing)       │
│ Train model (GPU)       │ 30 min    │ GPU (graph convolutions)│
│ Train model (CPU)       │ 2 hours   │ CPU (slow conv ops)     │
├─────────────────────────┼───────────┼──────────────────────────┤
│ TOTAL (GPU)             │ ~1 hour   │                         │
│ TOTAL (CPU)             │ ~2.5 hours│                         │
└─────────────────────────┴───────────┴──────────────────────────┘
```

## Dependencies Between Steps

```
Step 0 (Filter) ──────────────┐
                              │
                              ▼
Step 1 (Extract Code) ────────┐
                              │
                              ▼
Step 2 (Create Dataset) ──────┐
                              │
                              ▼
Step 3 (Train Model) ─────────┐
                              │
                              ▼
                        ✅ Trained Model
```

**Cannot skip steps:** Each step depends on output from previous step.

**Can re-run independently:** Once a step completes, its output file is cached.
- Example: After Step 2, can run Step 3 multiple times with different hyperparameters
- Example: After Step 1, can run Step 2 with different `max_safe_examples`

## Configuration-Driven Approach

All steps read from `configs/base_config.yaml`:

```yaml
data:
  advisories_path: "outputs/datasets/processed_advisories_with_code.json"
  codesearchnet_dir: "data/python/python/final/jsonl/train"
  processed_dataset_path: "outputs/datasets/final_graph_dataset.pt"

dataset:
  max_safe_examples: 200000
  max_nodes_per_graph: 100

model:
  hidden_channels: 128
  gcn_layers: 4
  gat_heads: 8
  dropout: 0.3

training:
  num_epochs: 20
  batch_size: 64
  learning_rate: 0.001
  patience: 5
```

**Benefit:** Change parameters without editing code. MLflow tracks all config values.

## Progress Tracking

Every long-running operation shows tqdm progress:

```
Step 0: Scanning advisory files: 100%|████████| 28143/28143 [00:28<00:00]
Step 1: Fetching commits: 100%|████████| 2847/2847 [15:23<00:00]
Step 2: Converting to graphs: 100%|████████| 201897/201897 [12:34<00:00]
Step 3: Epoch 5/20: 100%|████████| 3141/3141 [02:34<00:00] loss: 0.234
```

**Real-time metrics:**
- Items processed / Total items
- Time elapsed / Time remaining
- Processing rate (items/sec)
- Current loss/accuracy (training)
