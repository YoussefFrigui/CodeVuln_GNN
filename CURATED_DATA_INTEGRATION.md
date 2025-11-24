# Curated Data Integration Guide

## Overview

Your GNN vulnerability detection pipeline now integrates high-quality curated data! The system automatically uses the validated curated dataset when available, falling back to legacy format if needed.

## What Changed

### 1. **Enhanced Dataset Creation** (`src/create_dataset.py`)
- ✅ Automatically loads from `validated_vulnerabilities.json` (curated) if available
- ✅ Falls back to `processed_advisories_with_code.json` (legacy) if curated data missing
- ✅ Shows quality statistics during loading
- ✅ Tracks quality scores, CWE types, and fix availability

### 2. **Updated Pipeline Orchestrator** (`run_pipeline.py`)
- ✅ Added `--step curate` option for data curation
- ✅ Updated `--step all` to include curation step
- ✅ Smart file checking (accepts either curated or legacy data)

### 3. **Configuration** (`configs/base_config.yaml`)
- ✅ Added `sources.use_curated_vulnerabilities: true` flag
- ✅ Points to `validated_vulnerabilities.json` by default

## Usage

### Option 1: Full Pipeline (Recommended)
```bash
# Run complete pipeline with high-quality data
python run_pipeline.py --step all
```
This will:
1. Filter Python advisories
2. Extract vulnerable code from GitHub
3. **Curate and validate high-quality dataset** ✨
4. Create graph dataset
5. Train GNN model
6. Evaluate performance

### Option 2: Step-by-Step
```bash
# Step 1: Get raw advisory data
python run_pipeline.py --step filter
python run_pipeline.py --step preprocess

# Step 2: Curate high-quality dataset (NEW!)
python src/run_data_curation.py

# Step 3: Create graphs and train
python run_pipeline.py --step dataset
python run_pipeline.py --step train
python run_pipeline.py --step evaluate
```

### Option 3: Just Retrain with Curated Data
If you already have `validated_vulnerabilities.json`:
```bash
# Delete old dataset to force recreation
del outputs\datasets\final_graph_dataset.pt

# Create new dataset from curated data
python run_pipeline.py --step dataset

# Train with high-quality data
python run_pipeline.py --step train
```

## Data Quality Comparison

### Legacy Data (`processed_advisories_with_code.json`)
- ❌ ~10% syntax errors
- ❌ No quality scoring
- ❌ Limited CWE diversity
- ❌ ~50% have fixes
- ❌ No deduplication

### Curated Data (`validated_vulnerabilities.json`)
- ✅ 100% syntactically valid
- ✅ Quality scored (avg 0.59)
- ✅ 201 unique CWE types
- ✅ 94% have fixes (before/after pairs)
- ✅ Deduplicated
- ✅ Includes 20 synthetic examples
- ✅ Balanced across CWE types

## Expected Results

### Current Dataset Stats
From your curation run:
```
Total examples: 4,090
Average quality score: 0.592
Examples with fixes: 3,858 (94.3%)
Unique CWE types: 201

Top CWE Types:
- CWE-79 (XSS): 275
- CWE-502 (Deserialization): 250
- CWE-89 (SQL Injection): 123
- CWE-22 (Path Traversal): 196
- CWE-352 (CSRF): 120
```

### With CodeSearchNet (1:5 ratio)
Based on your config (`max_safe_examples: 36230`):
```
Dataset Composition:
- Vulnerable: 4,090 (curated)
- Safe: 36,230 (CodeSearchNet)
- Total: ~40,320 examples
- Ratio: 1:9 (vulnerable:safe)
```

**Note**: You might want to adjust `max_safe_examples` in `configs/base_config.yaml`:
- For 1:5 ratio: `max_safe_examples: 20450` (4,090 × 5)
- For 1:2 ratio: `max_safe_examples: 8180` (4,090 × 2)
- For 1:1 ratio: `max_safe_examples: 4090` (balanced)

## Configuration Options

### Use Curated Data (Default - Recommended)
```yaml
# configs/base_config.yaml
data:
  sources:
    use_curated_vulnerabilities: true  # High-quality curated data
```

### Use Legacy Data (Fallback)
```yaml
data:
  sources:
    use_curated_vulnerabilities: false  # Old format
```

### Adjust Quality Filtering
```yaml
dataset:
  quality:
    min_quality_score: 0.4  # Lower = more examples, higher = better quality
    min_loc: 5              # Minimum lines of code
    max_loc: 500            # Maximum lines of code
```

### Adjust CWE Diversity
```yaml
dataset:
  diversity:
    max_per_cwe: 150        # Max examples per CWE type
    balance_by_complexity: true
    include_synthetic: true
    synthetic_count: 200
```

## Troubleshooting

### "Missing required data files"
**Solution**: Run data curation first:
```bash
python src/run_data_curation.py
```

### "No vulnerable examples found"
**Solution**: Check file paths in config:
```bash
# Should exist:
dir outputs\datasets\validated_vulnerabilities.json

# Or regenerate:
python src/run_data_curation.py
```

### "Failed conversions: XX%"
This is normal! Some code snippets fail AST parsing:
- Legacy data: ~10% failure rate
- Curated data: <5% failure rate (syntax validated)

### Lower than expected dataset size
Check your config settings:
```yaml
dataset:
  quality:
    min_quality_score: 0.4  # Try lowering to 0.3
  diversity:
    max_per_cwe: 150  # Try increasing to 200
```

## Performance Impact

### Expected Improvements with Curated Data
- ✅ **Better vulnerable class recall** (fewer false negatives)
- ✅ **More balanced CWE coverage** (not just XSS/SQLi)
- ✅ **Lower training noise** (100% valid syntax)
- ✅ **Better generalization** (diverse vulnerability types)

### Training Time
- **Legacy**: ~2-3 hours (200k+ examples, 10% syntax errors)
- **Curated**: ~30-60 min (40k examples, 0% syntax errors)

## Next Steps

1. **Regenerate dataset** with curated data:
   ```bash
   python run_pipeline.py --step dataset
   ```

2. **Retrain model** with high-quality data:
   ```bash
   python run_pipeline.py --step train
   ```

3. **Compare performance** against old model:
   ```bash
   python run_pipeline.py --step evaluate
   ```

4. **Experiment with ratios**:
   - Try 1:1 ratio: `max_safe_examples: 4090`
   - Try 1:2 ratio: `max_safe_examples: 8180`
   - Try 1:5 ratio: `max_safe_examples: 20450`

5. **Optional: Add NVD data** for more diversity:
   ```bash
   # Get API key from https://nvd.nist.gov/developers/request-an-api-key
   set NVD_API_KEY=your_key_here
   
   # Edit config:
   # sources.nvd: true
   
   # Re-run curation:
   python src/run_data_curation.py
   ```

## Files Modified

1. ✅ `src/create_dataset.py` - Enhanced with curated data loading
2. ✅ `run_pipeline.py` - Added curation step
3. ✅ `configs/base_config.yaml` - Added `use_curated_vulnerabilities` flag

## Backward Compatibility

The system maintains full backward compatibility:
- If `validated_vulnerabilities.json` doesn't exist → uses legacy format
- If `use_curated_vulnerabilities: false` → forces legacy format
- All old scripts and workflows continue to work

## Questions?

Check these files for details:
- `DATA_CURATION_GUIDE.md` - How data curation works
- `src/data_quality/data_curator.py` - Curation implementation
- `src/data_quality/validator.py` - Validation logic
- `test_data_curation.py` - Test suite
