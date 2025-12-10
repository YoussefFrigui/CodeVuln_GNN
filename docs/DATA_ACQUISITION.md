# Data Acquisition Guide

This guide explains how to fetch and prepare vulnerability data for the GNN model.

## Overview

The data pipeline collects Python vulnerabilities from multiple sources:

1. **GitHub Security Advisory Database** - Primary source of vulnerability metadata
2. **GitHub API** - Fetches actual vulnerable code from commits
3. **Advisory Descriptions** - Extracts code snippets from description fields
4. **CodeSearchNet** - Provides "safe" code examples for the negative class

## Data Quality Hierarchy

| Source | Quality Score | Description |
|--------|---------------|-------------|
| Full file fetch | 0.9 | Complete Python files from GitHub Contents API |
| Curated examples | 0.8 | Manually verified vulnerable code |
| Diff-based | 0.6 | Code extracted from commit diffs |
| Description | 0.5 | Code snippets from advisory descriptions |

## Step 1: Clone Advisory Database

```bash
# Clone the GitHub Security Advisory Database
git clone https://github.com/github/advisory-database.git data/advisory-database
```

## Step 2: Filter Python Advisories

```bash
python src/filter_python_advisories.py
```

This creates `outputs/datasets/python_advisories.json` containing only PyPI advisories.

## Step 3: Fetch Full Files (Recommended)

The full file fetcher retrieves complete Python files from GitHub:

```bash
# First run - fetches all advisories with commit URLs
python src/fetch_full_files.py

# Resume if interrupted
python src/fetch_full_files.py --resume
```

**Features:**
- Saves progress every 10 examples (crash-safe)
- Caches raw responses in `outputs/cache/`
- Handles GitHub rate limiting with exponential backoff
- Falls back to diff extraction if full file unavailable

**Output:** `outputs/datasets/processed_advisories_full_files.json`

**GitHub Token (Optional but Recommended):**
```bash
set GITHUB_TOKEN=your_token_here
python src/fetch_full_files.py
```

Without a token: 60 requests/hour
With a token: 5,000 requests/hour

## Step 4: Extract Description Code

For advisories without commit URLs, extract code from descriptions:

```bash
python src/extract_description_code.py
```

**Output:** `outputs/datasets/description_extracted_code.json`

## Step 5: Merge All Sources

Combine all data sources with deduplication:

```bash
python src/merge_all_sources.py
```

This merges:
- Full file fetches (highest priority)
- Previously fetched diffs
- Description-extracted code
- Curated examples (if any)

**Output:** `outputs/datasets/merged_vulnerabilities.json`

## Step 6: Create Dataset

Now run the main pipeline:

```bash
python run_pipeline.py --step preprocess
```

This converts the merged vulnerabilities + CodeSearchNet safe examples into PyTorch Geometric graphs.

## File Reference

### Input Files
| File | Description |
|------|-------------|
| `data/advisory-database/` | Cloned GitHub Advisory Database |
| `data/python/python/final/jsonl/` | CodeSearchNet Python dataset |

### Output Files
| File | Description |
|------|-------------|
| `outputs/datasets/python_advisories.json` | Filtered PyPI advisories |
| `outputs/datasets/processed_advisories_full_files.json` | Full file fetches |
| `outputs/datasets/description_extracted_code.json` | Description-extracted code |
| `outputs/datasets/merged_vulnerabilities.json` | Combined dataset |
| `outputs/datasets/final_graph_dataset.pt` | PyTorch Geometric dataset |

### Cache Files
| File | Description |
|------|-------------|
| `outputs/cache/*.json` | Raw GitHub API responses |

## Estimated Times

| Step | Duration | Notes |
|------|----------|-------|
| Filter advisories | ~30 seconds | Scans ~10k JSON files |
| Fetch full files | 2-8 hours | Depends on GitHub rate limits |
| Extract descriptions | ~1 minute | Regex extraction |
| Merge sources | ~10 seconds | In-memory deduplication |
| Create dataset | 5-15 minutes | AST parsing + graph conversion |

## Troubleshooting

### "Rate limit exceeded"
- Set `GITHUB_TOKEN` environment variable
- The script will auto-wait for rate limit reset

### "Saved X examples" appears frequently
- Normal behavior - saves every 10 examples for crash recovery
- Use `--resume` to continue if script crashes

### Low number of full files fetched
- Many commits may have been deleted or repos made private
- Check `outputs/cache/` for cached failures
- Description extraction can supplement missing data

## Data Statistics (Expected)

After full pipeline:
- ~2,500-3,000 vulnerable examples (from ~7,000 advisories)
- ~200,000 safe examples (from CodeSearchNet)
- Class ratio: ~1:70 (handled by weighted loss)
