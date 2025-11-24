# High-Quality Data Curation Guide

## 🎯 Overview

This guide explains how to collect, curate, and validate high-quality diverse vulnerability data for improved model performance.

## 📊 Why Data Quality Matters

**Current Issues:**
- CodeSearchNet has syntax errors and incomplete code (~10% invalid)
- GitHub advisories may not isolate the vulnerability
- Severe class imbalance (1:50 vulnerable to safe)
- Limited CWE type diversity

**With High-Quality Curation:**
- ✅ Syntactically valid code (100%)
- ✅ Multiple vulnerability sources (GitHub, NVD, synthetic)
- ✅ Diverse CWE types (10+ categories)
- ✅ Quality scoring and validation
- ✅ Balanced representation

## 🚀 Quick Start

### 1. Install New Dependencies

```bash
pip install radon pylint
```

### 2. Run Data Curation Pipeline

```bash
# Basic curation (GitHub + Synthetic)
python src/run_data_curation.py
```

### 3. With NVD Integration (Recommended)

```bash
# Get API key from: https://nvd.nist.gov/developers/request-an-api-key
set NVD_API_KEY=your_api_key_here

# Enable NVD in config
# Edit configs/base_config.yaml: sources.nvd: true

python src/run_data_curation.py
```

## 📁 Data Sources

### 1. **GitHub Security Advisories** (Current)
- **Source:** GitHub Advisory Database
- **Quality:** Medium (needs validation)
- **Quantity:** ~7,246 examples
- **Coverage:** Real-world Python vulnerabilities

### 2. **Synthetic Vulnerabilities** (NEW!)
- **Source:** Generated from CWE templates
- **Quality:** High (controlled, valid)
- **Quantity:** Configurable (default 200)
- **Coverage:** 8 common CWE types
  - CWE-89: SQL Injection
  - CWE-79: Cross-Site Scripting (XSS)
  - CWE-78: Command Injection
  - CWE-502: Unsafe Deserialization
  - CWE-22: Path Traversal
  - CWE-798: Hardcoded Credentials
  - CWE-327: Weak Cryptography
  - CWE-918: Server-Side Request Forgery (SSRF)

### 3. **National Vulnerability Database** (Optional)
- **Source:** NVD API
- **Quality:** High (official CVE database)
- **Quantity:** Thousands of CVEs
- **Coverage:** Cross-project vulnerabilities

## ⚙️ Configuration

Edit `configs/base_config.yaml`:

```yaml
data:
  sources:
    github_advisories: true
    nvd: true  # Requires API key
    synthetic: true
    
dataset:
  quality:
    min_quality_score: 0.4  # Threshold (0-1)
    min_loc: 5  # Minimum lines of code
    max_loc: 500  # Maximum lines of code
    validate_syntax: true
    
  diversity:
    max_per_cwe: 150  # Balance CWE types
    balance_by_complexity: true
    include_synthetic: true
    synthetic_count: 200
```

## 🔍 Quality Validation

### Automatic Checks

Each example is validated for:

1. **Syntax Validity** - Must be valid Python
2. **Code Length** - Between 5-500 LOC
3. **Complexity** - Cyclomatic complexity > 1
4. **Content** - Not just comments or trivial code
5. **Vulnerability Indicators** - Contains suspicious patterns

### Quality Score Calculation

```python
score = base_score
+ 0.3 if has_fix (before/after pair)
+ 0.2 if has_cwe_classification
+ 0.2 if has_full_function_context
+ 0.2 if syntactically_valid
+ 0.1 if meaningful_description
```

**Threshold:** Only examples with `quality_score > 0.4` are kept

## 📈 Dataset Balancing

### CWE Type Balancing
- Maximum examples per CWE type (default: 150)
- Prevents over-representation of common vulnerabilities
- Ensures diverse vulnerability coverage

### Complexity Balancing
- Samples across complexity bins
- Ensures mix of simple and complex examples
- Better generalization

## 📝 Output Files

```
outputs/datasets/
├── curated_vulnerabilities.json      # Raw curated data
└── validated_vulnerabilities.json    # Validated & balanced
```

### Data Format

```json
{
  "examples": [
    {
      "id": "CVE-2023-12345",
      "source": "nvd",
      "cwe_id": "CWE-89",
      "severity": "HIGH",
      "vulnerable_code": "query = 'SELECT * FROM users WHERE id=' + user_id",
      "fixed_code": "query = 'SELECT * FROM users WHERE id=%s'; cursor.execute(query, (user_id,))",
      "description": "SQL injection via unsanitized user_id",
      "quality_score": 0.85,
      "complexity": 3.2,
      "loc": 12
    }
  ],
  "statistics": {
    "total_examples": 450,
    "cwe_types": 12,
    "avg_quality_score": 0.73
  }
}
```

## 🎨 Synthetic Vulnerability Generation

### How It Works

1. **CWE Templates:** Predefined patterns for each vulnerability type
2. **Variations:** Multiple variations per template (different variable names, contexts)
3. **Paired Data:** Both vulnerable and fixed versions
4. **Valid Code:** All synthetic code is syntactically correct

### Example: SQL Injection Template

```python
# Vulnerable (variation 1)
def search_users(user_input):
    query = "SELECT * FROM users WHERE name = '" + user_input + "'"
    cursor.execute(query)
    
# Fixed
def search_users(user_input):
    query = "SELECT * FROM users WHERE name = %s"
    cursor.execute(query, (user_input,))
```

### Benefits
- **Controlled Quality:** No syntax errors
- **Coverage:** Ensures all CWE types represented
- **Augmentation:** Increases training data
- **Educational:** Clear vulnerable vs. fixed patterns

## 📊 Expected Results

### Before Curation
```
Total: 7,246 vulnerable examples
Sources: GitHub Advisories only
Quality: ~90% valid (10% syntax errors)
CWE Types: 5-7 types
Balance: Highly imbalanced
```

### After Curation
```
Total: 400-600 high-quality examples
Sources: GitHub + Synthetic + NVD
Quality: 100% valid
CWE Types: 10-15 types
Balance: Balanced across types and complexity
Average Quality Score: 0.70+
```

## 🔄 Integration with Pipeline

### Update Your Workflow

**Old:**
```bash
python run_pipeline.py --step preprocess  # GitHub advisories only
python run_pipeline.py --step dataset
python run_pipeline.py --step train
```

**New:**
```bash
python run_pipeline.py --step preprocess  # GitHub advisories
python src/run_data_curation.py           # Curate high-quality data (NEW!)
python run_pipeline.py --step dataset     # Use curated data
python run_pipeline.py --step train
```

### Modify Dataset Creation

Update `src/create_dataset.py` to use curated data:

```python
# Load curated validated data
with open(config['data']['validated_dataset_path']) as f:
    curated_data = json.load(f)

for example in curated_data['examples']:
    vulnerable_code = example['vulnerable_code']
    graph = code_to_pyg_graph(vulnerable_code)
    if graph is not None:
        graphs.append(graph)
        labels.append(1)  # Vulnerable
```

## 🎯 Best Practices

### 1. Start with Synthetic
```bash
# Quick test with just synthetic data
python src/run_data_curation.py
# Should generate 200 examples in ~30 seconds
```

### 2. Add NVD for Production
```bash
# Get NVD API key (free)
# Add 500+ real CVEs with fixes
NVD_API_KEY=your_key python src/run_data_curation.py
```

### 3. Monitor Quality Scores
- Check `avg_quality_score` in output
- Aim for > 0.70
- Adjust `min_quality_score` in config if needed

### 4. Balance Your Dataset
- Check CWE distribution
- Increase `max_per_cwe` if types are underrepresented
- Enable `balance_by_complexity` for better generalization

## 🔧 Troubleshooting

### "No examples added"
**Cause:** Quality threshold too high  
**Fix:** Lower `min_quality_score` in config to 0.3

### "Too few CWE types"
**Cause:** Missing data sources  
**Fix:** Enable NVD or increase synthetic count

### "Synthetic code has errors"
**Cause:** Template bug (rare)  
**Fix:** Report issue, skip that CWE type in config

### "NVD rate limit"
**Cause:** No API key (10 req/min limit)  
**Fix:** Get free API key for 50 req/min

## 📚 Next Steps

1. **Run curation:** `python src/run_data_curation.py`
2. **Review quality:** Check `validated_vulnerabilities.json`
3. **Update dataset script:** Use curated data
4. **Retrain model:** Should see improved performance
5. **Iterate:** Adjust quality/diversity settings based on results

## 🎓 Advanced: Hard Negative Mining

Coming soon! Mine similar but safe code as hard negatives:

```python
# Find safe code that uses similar APIs but correctly
curator.mine_hard_negatives(
    safe_code_dir='data/python',
    count=500
)
```

## 💡 Tips for Production

1. **Version your data:** Add version to metadata
2. **Track provenance:** Record source for each example
3. **Audit regularly:** Re-validate periodically
4. **A/B test:** Compare models trained on old vs. curated data
5. **Monitor CWE coverage:** Track emerging vulnerability types

---

**Questions?** Check `src/data_quality/data_curator.py` for implementation details.
