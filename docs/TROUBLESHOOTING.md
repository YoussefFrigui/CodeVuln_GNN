# Troubleshooting Guide

Common issues and solutions for the GNN vulnerability detection system.

## Data Acquisition Issues

### "Rate limit exceeded" during fetching

**Symptom:** Script stops with 403 error or rate limit message

**Solution:**
```bash
# Set GitHub token (5000 requests/hour vs 60)
set GITHUB_TOKEN=ghp_your_token_here
python src/fetch_full_files.py --resume
```

Get a token at: https://github.com/settings/tokens (no special permissions needed)

### Few files fetched despite many advisories

**Symptom:** Only ~500 files from 3000 advisories

**Causes:**
- Repositories deleted or made private
- Commits force-pushed/rebased away
- Files renamed/moved since vulnerability

**Solution:**
- This is expected - not all commits are accessible
- Description extraction supplements missing data:
  ```bash
  python src/extract_description_code.py
  python src/merge_all_sources.py
  ```

### "FileNotFoundError: advisory-database"

**Symptom:** Pipeline can't find advisory data

**Solution:**
```bash
git clone https://github.com/github/advisory-database.git data/advisory-database
```

---

## Training Issues

### Out of Memory (OOM)

**Symptom:** CUDA out of memory error during training

**Solutions (try in order):**

1. Reduce batch size:
   ```yaml
   # configs/base_config.yaml
   training:
     batch_size: 32  # try 16, 8
   ```

2. Reduce graph size:
   ```yaml
   dataset:
     max_nodes_per_graph: 50
   ```

3. Reduce model size:
   ```yaml
   model:
     hidden_channels: 64
     gat_heads: 2
   ```

4. Use CPU (slow but works):
   ```yaml
   training:
     device: "cpu"
   ```

### Model predicts all "safe" (0% vulnerable recall)

**Symptom:** Accuracy looks high but vulnerable F1 is 0

**Causes:**
- Class weights not applied
- Extreme class imbalance

**Diagnosis:**
```python
# Check weights in training output
# Should see something like: weights=[0.5, 26.0]
```

**Solution:**
Verify `train_gnn.py` calculates and applies class weights:
```python
class_weights = compute_class_weight(...)
criterion = nn.CrossEntropyLoss(weight=class_weights)
```

### Training appears frozen

**Symptom:** No output for minutes

**Causes:**
- Missing tqdm progress bars
- Very large dataset loading

**Solution:**
Check that training loop uses tqdm:
```python
for batch in tqdm(loader, desc="Training"):
    ...
```

### Validation loss oscillates wildly

**Symptom:** Val loss jumps between 0.1 and 2.0

**Solutions:**
1. Lower learning rate:
   ```yaml
   training:
     learning_rate: 0.0001
   ```

2. Increase batch size (if memory allows):
   ```yaml
   training:
     batch_size: 128
   ```

### "No module named 'torch_geometric'"

**Symptom:** Import error on startup

**Solution:**
```bash
# Install PyTorch Geometric (version must match PyTorch)
pip install torch-geometric
pip install torch-scatter torch-sparse torch-cluster -f https://data.pyg.org/whl/torch-2.0.0+cu118.html
```

Adjust URL for your PyTorch and CUDA versions.

---

## Dataset Issues

### "SyntaxError" during graph conversion

**Symptom:** Many None graphs, low conversion rate

**Cause:** Invalid Python code in dataset

**Solution:**
This is expected for ~5-10% of CodeSearchNet data. The `fix_incomplete_code()` function in `graph_utils.py` handles common cases. Monitor:
```
Created X graphs from Y examples (Z% conversion rate)
```
80%+ is acceptable.

### Dataset too small

**Symptom:** Only ~100 vulnerable examples

**Diagnosis:**
```bash
# Check intermediate files
python -c "import json; d=json.load(open('outputs/datasets/merged_vulnerabilities.json')); print(len(d))"
```

**Solution:**
1. Run full file fetcher (takes hours)
2. Run description extraction
3. Run merge script
4. Regenerate dataset

### "KeyError: 'code'" during dataset creation

**Symptom:** Script crashes reading vulnerabilities

**Cause:** Old file format

**Solution:**
Ensure using merged file which has consistent format:
```yaml
data:
  advisories_path: "outputs/datasets/merged_vulnerabilities.json"
```

---

## Evaluation Issues

### Confusion matrix looks wrong

**Symptom:** Only diagonal or single cell has values

**Cause:** All predictions same class

**Solution:**
- Check class weights applied
- Try balanced dataset for debugging:
  ```yaml
  dataset:
    max_safe_examples: 4000  # Match vulnerable count
  ```

### Metrics don't match expectations

**Symptom:** Paper reports 95% but you get 60%

**Causes:**
- Different dataset split
- Different preprocessing
- Overfitting in paper

**Solution:**
- Use stratified splits (already implemented)
- Report per-class metrics, not just accuracy
- Use cross-validation for robust estimates

---

## Environment Issues

### Python version conflicts

**Symptom:** Syntax errors or import failures

**Solution:**
Use Python 3.9+:
```bash
python --version  # Should be 3.9+
```

### GPU not detected

**Symptom:** Training uses CPU despite having GPU

**Diagnosis:**
```python
import torch
print(torch.cuda.is_available())  # Should be True
print(torch.cuda.get_device_name(0))
```

**Solution:**
1. Install CUDA-enabled PyTorch:
   ```bash
   pip install torch --index-url https://download.pytorch.org/whl/cu118
   ```

2. Check NVIDIA drivers:
   ```bash
   nvidia-smi
   ```

### OneDrive sync conflicts

**Symptom:** Files not deleted, duplicate files

**Solution:**
- Pause OneDrive sync during intensive operations
- Or move project outside OneDrive folder

---

## Quick Diagnostic Commands

```bash
# Check PyTorch Geometric installation
python -c "import torch_geometric; print(torch_geometric.__version__)"

# Check CUDA
python -c "import torch; print(f'CUDA: {torch.cuda.is_available()}')"

# Check dataset size
python -c "import torch; d=torch.load('outputs/datasets/final_graph_dataset.pt'); print(f'Graphs: {len(d)}')"

# Check config
python -c "import yaml; c=yaml.safe_load(open('configs/base_config.yaml')); print(c)"

# Check vulnerable count
python -c "import json; d=json.load(open('outputs/datasets/merged_vulnerabilities.json')); print(f'Vulnerable: {len(d)}')"
```

---

## Getting Help

1. Check this guide first
2. Review the copilot-instructions.md for project context
3. Check git history for what's been tried
4. Run diagnostic commands above
5. Include error messages and config when asking for help
