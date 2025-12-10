"""
Merge All Vulnerable Code Sources

This script combines vulnerable code from multiple sources into a single dataset:

1. Full file fetches (highest quality) - from fetch_full_files.py
2. Original diff-based data (medium quality) - processed_advisories_with_code.json
3. Description-extracted code (lower quality) - from extract_description_code.py
4. Curated/validated data (if available)

The merge prioritizes quality:
- If same advisory exists in multiple sources, prefer full file > diff > description
- Deduplicates by code hash to avoid training on duplicates

Usage:
    python src/merge_all_sources.py

Output:
    outputs/datasets/merged_vulnerabilities.json
"""

import json
import os
from typing import Dict, List, Any, Set
from collections import defaultdict
from tqdm import tqdm


def load_json_safe(path: str) -> List[Dict]:
    """Load JSON file, return empty list if not found."""
    if os.path.exists(path):
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            # Handle both list and dict with 'examples' key
            if isinstance(data, dict) and 'examples' in data:
                return data['examples']
            return data if isinstance(data, list) else []
    return []


def get_code_hash(code: str) -> int:
    """Get hash of normalized code for deduplication."""
    # Normalize whitespace for comparison
    normalized = ' '.join(code.split())
    return hash(normalized)


def merge_all_sources(
    full_files_path: str = 'outputs/datasets/processed_advisories_full_files.json',
    diff_based_path: str = 'outputs/datasets/processed_advisories_with_code.json',
    description_path: str = 'outputs/datasets/description_extracted_code.json',
    curated_path: str = 'outputs/datasets/curated_vulnerabilities.json',
    validated_path: str = 'outputs/datasets/validated_vulnerabilities.json',
) -> List[Dict[str, Any]]:
    """
    Merge all vulnerability sources with quality-based priority.
    
    Priority (highest first):
    1. Full file fetches (quality_score ~0.9)
    2. Curated/validated data (quality_score ~0.8)
    3. Diff-based data (quality_score ~0.6)
    4. Description-extracted (quality_score ~0.5)
    """
    
    print("=" * 70)
    print("🔀 Merging All Vulnerability Data Sources")
    print("=" * 70)
    
    merged = []
    seen_codes: Set[int] = set()
    seen_advisory_files: Dict[str, Dict] = {}  # advisory_id+filename -> best example
    
    stats = defaultdict(int)
    
    # Source 1: Full file fetches (highest priority)
    print(f"\n📁 Loading full file fetches from {full_files_path}...")
    full_files = load_json_safe(full_files_path)
    print(f"   Found {len(full_files)} examples")
    stats['full_files_input'] = len(full_files)
    
    for ex in full_files:
        code = ex.get('vulnerable_code', '').strip()
        if len(code) < 20:
            continue
            
        code_hash = get_code_hash(code)
        key = f"{ex.get('advisory_id', '')}:{ex.get('filename', '')}"
        
        if code_hash not in seen_codes:
            seen_codes.add(code_hash)
            ex['source'] = 'full_file_fetch'
            ex['quality_score'] = ex.get('quality_score', 0.9)
            seen_advisory_files[key] = ex
            stats['full_files_added'] += 1
    
    # Source 2: Curated/validated data
    for path, name in [(validated_path, 'validated'), (curated_path, 'curated')]:
        print(f"\n📁 Loading {name} data from {path}...")
        curated = load_json_safe(path)
        print(f"   Found {len(curated)} examples")
        stats[f'{name}_input'] = len(curated)
        
        for ex in curated:
            code = ex.get('vulnerable_code', ex.get('code', '')).strip()
            if len(code) < 20:
                continue
                
            code_hash = get_code_hash(code)
            key = f"{ex.get('advisory_id', ex.get('id', ''))}:{ex.get('filename', '')}"
            
            # Only add if not already seen
            if code_hash not in seen_codes:
                seen_codes.add(code_hash)
                new_ex = {
                    'advisory_id': ex.get('advisory_id', ex.get('id', '')),
                    'summary': ex.get('summary', ''),
                    'severity': ex.get('severity', 'MEDIUM'),
                    'cwe_id': ex.get('cwe_id', ''),
                    'cwe_ids': ex.get('cwe_ids', []),
                    'vulnerable_code': code,
                    'fixed_code': ex.get('fixed_code', ''),
                    'fetch_method': name,
                    'is_complete_file': ex.get('is_complete_file', False),
                    'quality_score': ex.get('quality_score', 0.8),
                    'source': name
                }
                seen_advisory_files[key] = new_ex
                stats[f'{name}_added'] += 1
    
    # Source 3: Diff-based data
    print(f"\n📁 Loading diff-based data from {diff_based_path}...")
    diff_based = load_json_safe(diff_based_path)
    print(f"   Found {len(diff_based)} examples")
    stats['diff_based_input'] = len(diff_based)
    
    for ex in diff_based:
        code = ex.get('vulnerable_code', '').strip()
        if len(code) < 20:
            continue
            
        code_hash = get_code_hash(code)
        key = f"{ex.get('advisory_id', '')}:{ex.get('filename', '')}"
        
        # Only add if not already seen (full file or curated didn't have it)
        if code_hash not in seen_codes:
            seen_codes.add(code_hash)
            ex['source'] = 'diff_based'
            ex['fetch_method'] = ex.get('fetch_method', 'diff_only')
            ex['quality_score'] = ex.get('quality_score', 0.6)
            ex['is_complete_file'] = False
            seen_advisory_files[key] = ex
            stats['diff_based_added'] += 1
    
    # Source 4: Description-extracted code (lowest priority)
    print(f"\n📁 Loading description-extracted from {description_path}...")
    description = load_json_safe(description_path)
    print(f"   Found {len(description)} examples")
    stats['description_input'] = len(description)
    
    for ex in description:
        code = ex.get('vulnerable_code', '').strip()
        if len(code) < 20:
            continue
            
        code_hash = get_code_hash(code)
        
        # Only add if code not seen anywhere else
        if code_hash not in seen_codes:
            seen_codes.add(code_hash)
            ex['source'] = 'description_extraction'
            ex['quality_score'] = 0.5
            merged.append(ex)
            stats['description_added'] += 1
    
    # Combine all
    merged = list(seen_advisory_files.values()) + merged
    
    # Print statistics
    print("\n" + "=" * 70)
    print("📊 Merge Statistics")
    print("=" * 70)
    
    print(f"\n   Source                    | Input  | Added  | Quality")
    print(f"   " + "-" * 55)
    print(f"   Full file fetches         | {stats['full_files_input']:>6} | {stats['full_files_added']:>6} | 0.9")
    print(f"   Validated data            | {stats['validated_input']:>6} | {stats['validated_added']:>6} | 0.8")
    print(f"   Curated data              | {stats['curated_input']:>6} | {stats['curated_added']:>6} | 0.8")
    print(f"   Diff-based data           | {stats['diff_based_input']:>6} | {stats['diff_based_added']:>6} | 0.6")
    print(f"   Description extraction    | {stats['description_input']:>6} | {stats['description_added']:>6} | 0.5")
    print(f"   " + "-" * 55)
    print(f"   TOTAL UNIQUE              |        | {len(merged):>6} |")
    
    # Source distribution
    source_counts = defaultdict(int)
    for ex in merged:
        source_counts[ex.get('source', 'unknown')] += 1
    
    print(f"\n   Final source distribution:")
    for source, count in sorted(source_counts.items(), key=lambda x: -x[1]):
        pct = 100 * count / len(merged)
        print(f"     {source}: {count} ({pct:.1f}%)")
    
    # Quality distribution
    high_quality = sum(1 for ex in merged if ex.get('quality_score', 0) >= 0.8)
    medium_quality = sum(1 for ex in merged if 0.5 < ex.get('quality_score', 0) < 0.8)
    low_quality = sum(1 for ex in merged if ex.get('quality_score', 0) <= 0.5)
    
    print(f"\n   Quality distribution:")
    print(f"     High (≥0.8):   {high_quality} ({100*high_quality/len(merged):.1f}%)")
    print(f"     Medium:        {medium_quality} ({100*medium_quality/len(merged):.1f}%)")
    print(f"     Low (≤0.5):    {low_quality} ({100*low_quality/len(merged):.1f}%)")
    
    return merged


def main():
    merged = merge_all_sources()
    
    # Save merged data
    output_path = 'outputs/datasets/merged_vulnerabilities.json'
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(merged, f, indent=2)
    
    print(f"\n💾 Saved {len(merged)} merged examples to {output_path}")
    
    # Update config hint
    print(f"\n📝 To use merged data, update configs/base_config.yaml:")
    print(f"   data:")
    print(f"     advisories_path: 'outputs/datasets/merged_vulnerabilities.json'")
    
    print(f"\n✅ Merge complete!")


if __name__ == "__main__":
    main()
