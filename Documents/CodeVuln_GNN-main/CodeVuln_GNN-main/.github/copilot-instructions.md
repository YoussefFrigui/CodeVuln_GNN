# GNN-Based Python Vulnerability Detection

## AI Agent Guidelines

When working on this project, AI agents should:

### 1. Analysis Protocol
- **Always read `configs/base_config.yaml` first** to understand current parameters before making changes
- Check for existing `.pt` and `.json` files to assess what data processing stages are complete
- Review recent commits in Git history to understand what's been tried
- Scan `PROJECT_PROGRESS*.md` and `00_EXECUTIVE_SUMMARY.md` for known issues and historical context

### 2. Documentation Requirements
- **Update PROJECT_PROGRESS_2.md** when completing significant milestones (dataset changes, model improvements, new features)
- Document parameter changes in commit messages with rationale (e.g., "Reduced batch_size from 64 to 32 due to OOM on 8GB GPU")
- Add inline comments explaining non-obvious decisions (especially in graph conversion and loss calculation)
- Keep a changelog of experiments: what was tried, what worked, what failed

### 3. Code Quality Standards
- **Never hardcode paths or hyperparameters** - always use `configs/base_config.yaml`
- Maintain consistent error handling: log failures, don't silently ignore (except intentional cases like malformed CodeSearchNet data)
- Add type hints to all new functions (see `src/data_processing/graph_utils.py` as reference)
- Use descriptive variable names: `num_vulnerable_samples` not `n_v`

### 4. Testing & Validation
- Before proposing model changes, verify the current baseline performance first
- After modifying graph conversion, test on a small sample (10-100 examples) before full dataset
- Always validate config changes don't break backward compatibility with existing `.pt` files
- Check GPU memory usage when increasing batch_size or model complexity

### 5. Suggesting Improvements
- **Prioritize reproducibility fixes** (versioning dependencies, removing absolute paths, adding random seeds)
- Suggest modular refactoring over adding features to monolithic scripts
- When proposing architecture changes, cite relevant papers or PyTorch Geometric examples
- Consider class imbalance impact - any sampling change affects the 1:50 ratio

### 6. Common Tasks Workflow
- **Adding new features to AST graphs**: Update `NODE_TYPES` dict → adjust `num_node_features` in config → regenerate dataset
- **Changing model architecture**: Edit `src/modeling/model.py` → update config parameters → retrain without regenerating data
- **Debugging low vulnerable class recall**: Check class weights calculation → verify stratified splits → examine loss weights
- **Optimizing memory**: Reduce `batch_size`, `max_nodes_per_graph`, or `max_safe_examples` in config

## Project Architecture

This is a Graph Neural Network (GNN) system for detecting security vulnerabilities in Python code by analyzing Abstract Syntax Trees (ASTs). The architecture combines:
- **Data Sources**: GitHub Security Advisory database (vulnerable code) + CodeSearchNet (safe code examples)
- **Graph Representation**: AST nodes become graph nodes with type-based features; parent-child relationships become edges
- **GNN Model**: 4-layer GCN + GAT attention layer + MLP classifier (in `src/modeling/model.py`)
- **Training Scale**: 200k+ code samples with 1:50 vulnerable-to-safe class imbalance

## Configuration-Driven Workflow

**ALL runtime parameters live in `configs/base_config.yaml`** - never hardcode paths, hyperparameters, or dataset sizes. The config drives:
- Data paths (advisories, CodeSearchNet, output files)
- Dataset parameters (max_safe_examples, max_nodes_per_graph)
- Model architecture (hidden_channels, gcn_layers, gat_heads, dropout)
- Training settings (num_epochs, batch_size, learning_rate, early stopping patience)

Example: To experiment with dataset size, modify `dataset.max_safe_examples` in the config, not in code.

## Critical Execution Pattern: Pipeline Orchestration

Use `run_pipeline.py` as the single entry point:
```bash
python run_pipeline.py --step all           # Full pipeline
python run_pipeline.py --step preprocess    # Data only
python run_pipeline.py --step train         # Training only
```

**NEVER** run scripts directly (`python scripts/01_create_dataset.py`) except for debugging. The orchestrator handles:
- Dependency checking (PyTorch, torch-geometric, networkx)
- Data file validation (checks for required .pt and .json files)
- Sequential execution with proper error propagation

## Code-to-Graph Conversion (src/data_processing/graph_utils.py)

The `code_to_pyg_graph()` function is the core transformation:
1. Parse Python code with `ast.parse()` → AST tree
2. Convert AST to NetworkX DiGraph via `ast_to_graph()` (recursive traversal, max 100 nodes)
3. Create node features: AST node type mapped to integer (see `NODE_TYPES` dict with 48+ types)
4. Pad features to fixed 11-dimensional vectors
5. Convert to PyTorch Geometric `Data` object

**Important**: Syntax errors are silently caught and return `None` - this is intentional for handling imperfect CodeSearchNet data.

## Class Imbalance Handling (CRITICAL)

With 1:50 vulnerable-to-safe ratio, raw training fails (model predicts "safe" for everything). Solutions implemented:
- **Weighted Cross-Entropy Loss**: Calculated in `scripts/02_train_model.py` using `total/(2*class_count)` formula
- **Stratified Splitting**: Both `train_test_split()` calls use `stratify=labels` to maintain class ratios
- **Result**: Vulnerable class receives ~26x higher loss weight

## Data Pipeline Architecture

**Two-stage dataset creation** (avoid confusion between file formats):

1. **Raw Advisory Processing** (`src/filter_python_advisories.py` → `python_advisories.json`)
   - Scans `data/advisory-database/advisories/github-reviewed/**/*.json`
   - Filters for `ecosystem: PyPI` advisories
   - Does NOT extract code yet

2. **Graph Dataset Creation** (`scripts/01_create_dataset.py` → `massive_codesearchnet_dataset.pt`)
   - Loads vulnerable code from processed advisories
   - Streams safe code from CodeSearchNet `.jsonl` files (uses `original_string` field)
   - Converts all to PyTorch Geometric graphs
   - Saves single `.pt` file (not splits - splitting happens during training)

## Training Patterns

**The Trainer class in `scripts/02_train_model.py`** follows this structure:
- `train_epoch()`: Returns (loss, accuracy) for the training set
- `evaluate()`: Returns dict with loss, accuracy, precision, recall, F1
- `run_training()`: Main loop with early stopping (monitors validation loss, saves best model state)

**Early stopping logic**: If validation loss doesn't improve for `patience` epochs (default 5), training stops and best model is restored.

**Device selection**: `device: "auto"` in config → uses CUDA if available, else CPU. Access via `get_device()` function.

## File Naming Conventions

- `massive_*.pt` = Full 200k+ dataset files
- `processed_graphs.pt` = Converted graph dataset
- `data_splits.pt` = Train/val/test splits (legacy - newer code uses inline splitting)
- `vulnerability_gnn_model.pt` = Trained model weights
- `*_advisories.json` = Advisory data (human-readable JSON)

## Common Development Workflows

**To experiment with model architecture**:
1. Edit `configs/base_config.yaml` → `model` section
2. Run `python run_pipeline.py --step train` (skips data preprocessing)

**To add new AST node types**:
1. Add to `NODE_TYPES` dict in `src/data_processing/graph_utils.py`
2. Increment `UNKNOWN_NODE_TYPE` value
3. Update `configs/base_config.yaml` → `model.num_node_features` to match

**To debug parsing failures**:
- Check `code_to_pyg_graph()` - it catches SyntaxError and returns None
- Add logging before the try-except to see which code snippets fail

## Dependencies & Environment

**PyTorch Geometric installation is tricky** - requires matching versions of:
- `torch`, `torch-geometric`, `torch-scatter`, `torch-sparse`, `torch-cluster`
- Follow PyG installation guide: https://pytorch-geometric.readthedocs.io/en/latest/install/installation.html
- Check CUDA version compatibility if using GPU

**Required data setup**:
1. Clone GitHub Advisory Database: `git clone https://github.com/github/advisory-database.git data/advisory-database`
2. Download CodeSearchNet Python dataset from Kaggle to `data/python/python/final/jsonl/train/`

## Progress Tracking System

The training scripts use `tqdm` for real-time visibility (see `scripts/02_train_model.py`):
- Epoch-level: Outer loop shows epoch progress
- Batch-level: `train_epoch()` and `evaluate()` have `tqdm(loader, desc="...")` 
- Metrics displayed: `set_postfix({'loss': ..., 'acc': ...})`

**Why this matters**: With 200k+ samples, training takes hours. Without progress bars, the system appears frozen.

## Known Limitations & Warnings

1. **Memory constraints**: Default `batch_size: 64` requires ~8GB GPU memory. Reduce if OOM occurs.
2. **AST node limit**: `max_nodes_per_graph: 100` truncates large functions. Complex code may lose structure.
3. **CodeSearchNet quality**: Contains syntax errors and incomplete snippets. ~5-10% of samples are silently skipped.
4. **Reproducibility issues**: Random seed is set (`random_state: 42`) but PyTorch Geometric graph operations may have non-determinism.

## Testing & Evaluation

**No unit tests exist** (see `00_EXECUTIVE_SUMMARY.md` for critique). Manual evaluation via:
```bash
python run_pipeline.py --step evaluate
```
Outputs confusion matrix PNG and prints classification metrics (accuracy, precision, recall, F1).

## When to Modify Core Files

- **`src/modeling/model.py`**: Change GNN architecture (add layers, change pooling strategy)
- **`src/data_processing/graph_utils.py`**: Modify feature extraction (e.g., add edge features, change node representation)
- **`scripts/01_create_dataset.py`**: Alter data loading logic (e.g., use different CodeSearchNet fields)
- **`scripts/02_train_model.py`**: Change training loop (e.g., add learning rate scheduling, modify loss function)

**Do NOT modify** `run_pipeline.py` unless changing the orchestration logic itself.

## Project-Specific Best Practices

### Code Organization
- Keep data processing logic in `src/data_processing/`
- Keep model definitions in `src/modeling/`
- Keep training logic in `src/training/` or `scripts/`
- **Anti-pattern**: Adding model training code to data processing scripts

### Configuration Management
- When adding new parameters, add them to `base_config.yaml` with comments explaining purpose
- Group related parameters (e.g., all model architecture params under `model:`)
- Provide sensible defaults that work on 16GB RAM + 8GB GPU

### Performance Optimization
- Use `tqdm` for any loop processing >1000 items
- Implement early stopping to avoid wasting compute on plateaued training
- Cache processed datasets as `.pt` files - don't reprocess from source every run
- **Memory tip**: Process CodeSearchNet files one at a time using generators, not loading all into RAM

### Handling Imbalanced Data
- Always report per-class metrics (precision/recall/F1), not just overall accuracy
- When changing dataset size, recalculate class weights in training script
- Consider techniques like SMOTE or focal loss if weighted CE isn't sufficient

### Git Workflow
- Commit config changes separately from code changes
- Tag commits that produce important model checkpoints (e.g., `v1.0-baseline-99acc`)
- Don't commit large `.pt` files - use Git LFS or document download instructions
- Use descriptive branch names: `feature/edge-features`, `fix/oom-errors`, `experiment/focal-loss`

## Troubleshooting Guide for AI Agents

### Problem: "Model predicts all safe (0% recall on vulnerable class)"
**Diagnosis**: Class imbalance not handled
**Solution**: Verify weighted loss calculation in `scripts/02_train_model.py` - should show weights like `[0.5, 26.0]`

### Problem: "OOM (Out of Memory) during training"
**Diagnosis**: Batch too large or graphs too complex
**Solution**: Reduce `batch_size` in config (try 32 → 16 → 8), or reduce `max_nodes_per_graph` (try 100 → 50)

### Problem: "Training appears frozen with no output"
**Diagnosis**: Missing progress bars
**Solution**: Verify `tqdm` is wrapping data loaders in train/eval functions

### Problem: "Results not reproducible between runs"
**Diagnosis**: Random seed not set or non-deterministic operations
**Solution**: Check `random_state: 42` in config is being used in all `train_test_split()` calls

### Problem: "Many graphs returning None during conversion"
**Diagnosis**: Syntax errors in source code or empty functions
**Solution**: This is expected for ~5-10% of CodeSearchNet. Log count of successful vs failed conversions to monitor

### Problem: "Validation loss oscillates wildly"
**Diagnosis**: Learning rate too high or batch size too small
**Solution**: Try `learning_rate: 0.0001` (10x lower) or increase `batch_size` if memory allows

## Current State & Known Issues

**As of November 2025:**
- ✅ Dataset: 202,526 examples (3,928 vulnerable + 198,598 safe)
- ✅ Model: 4-layer GCN + GAT working with 99%+ accuracy
- ✅ Training: Weighted loss handles imbalance effectively
- ⚠️ No unit tests (see `00_EXECUTIVE_SUMMARY.md` critique)
- ⚠️ Hardcoded paths in some legacy scripts (being migrated to config-driven)
- ⚠️ No MLOps integration (no experiment tracking, no versioning of datasets)

**Priority Improvements Needed:**
1. Add experiment tracking (MLflow or Weights & Biases)
2. Create unit tests for graph conversion and model forward pass
3. Version control for datasets (track which advisory DB version was used)
4. Add edge features to graphs (currently only using node features)
5. Implement cross-validation for more robust evaluation
