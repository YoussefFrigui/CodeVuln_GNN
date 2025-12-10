"""
Dataset Creation Script

This script generates a massive, labeled dataset for training a vulnerability
detection model. It combines vulnerable code examples from the GitHub Security
Advisory database with safe code examples from the CodeSearchNet dataset.

The script performs the following steps:
1. Loads vulnerable code examples from a JSON file of advisories.
2. Loads safe code examples from the CodeSearchNet JSONL files.
3. Converts each code snippet into a PyTorch Geometric graph representation.
4. Balances the dataset according to the specified configuration.
5. Saves the final dataset as a single PyTorch file.

This script is designed to be run once to prepare the data for training.
"""

import json
import os
from typing import List, Dict, Any, Iterator

import torch
from tqdm import tqdm
import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent))
from data_processing.graph_utils import code_to_pyg_graph


def load_vulnerable_examples(advisories_path: str, use_curated: bool = True, 
                            curated_path: str = None) -> List[Dict[str, Any]]:
    """
    Loads vulnerable code examples from BOTH raw advisories AND curated dataset.
    
    This function combines data from multiple sources for maximum coverage:
    1. Raw processed advisories - All 7000+ examples from GitHub advisories
    2. Curated dataset (if available) - Additional validated, high-quality examples

    Args:
        advisories_path: Path to the processed advisories JSON file.
        use_curated: If True, also loads from curated dataset.
        curated_path: Path to curated/validated dataset JSON file.

    Returns:
        A list of dictionaries with vulnerable code snippets.
    """
    vulnerable_examples = []
    seen_codes = set()  # Deduplicate by code hash
    
    # ALWAYS load from raw processed advisories first (main source - 7000+ examples)
    if os.path.exists(advisories_path):
        print(f"Loading vulnerable examples from {advisories_path}...")
        
        with open(advisories_path, "r", encoding="utf-8") as f:
            advisories = json.load(f)
        
        for advisory in advisories:
            if "vulnerable_code" in advisory and advisory["vulnerable_code"]:
                code = advisory["vulnerable_code"].strip()
                code_hash = hash(code)
                
                # Filter: code > 20 chars and not duplicate
                if len(code) > 20 and code_hash not in seen_codes:
                    seen_codes.add(code_hash)
                    
                    # Get CWE ID - handle both string and list formats
                    cwe_id = advisory.get("cwe_id", "")
                    if not cwe_id and advisory.get("cwe_ids"):
                        cwe_id = advisory["cwe_ids"][0] if advisory["cwe_ids"] else ""
                    
                    vulnerable_examples.append({
                        "code": code,
                        "label": 1,  # 1 = vulnerable
                        "advisory_id": advisory.get("advisory_id", advisory.get("id", "")),
                        "filename": advisory.get("filename", ""),
                        "cwe_id": cwe_id,
                        "severity": advisory.get("severity", "MEDIUM"),
                        "quality_score": advisory.get("quality_score", 0.6),
                        "source": "github_advisory",
                        "is_complete_file": advisory.get("is_complete_file", False),
                        "fetch_method": advisory.get("fetch_method", "diff_only"),
                    })
        
        print(f"✓ Loaded {len(vulnerable_examples)} examples from raw advisories")
        
        # Show stats for complete vs partial files
        complete_files = sum(1 for ex in vulnerable_examples if ex.get("is_complete_file", False))
        partial_files = len(vulnerable_examples) - complete_files
        if complete_files > 0 or partial_files > 0:
            print(f"   📁 Complete files: {complete_files} ({100*complete_files/len(vulnerable_examples):.1f}%)")
            print(f"   📄 Partial diffs:  {partial_files} ({100*partial_files/len(vulnerable_examples):.1f}%)")
    
    # ALSO load from curated/validated dataset if available (adds extra quality examples)
    if use_curated and curated_path and os.path.exists(curated_path):
        print(f"Loading additional curated examples from {curated_path}...")
        
        with open(curated_path, "r", encoding="utf-8") as f:
            curated_data = json.load(f)
        
        # Handle new curated format with metadata
        if "examples" in curated_data:
            examples = curated_data["examples"]
            stats = curated_data.get("validation_stats", curated_data.get("statistics", {}))
            
            if stats:
                print(f"📊 Curated Dataset Statistics:")
                print(f"   Total: {stats.get('total_examples', stats.get('total', len(examples)))}")
                print(f"   Valid: {stats.get('valid_examples', stats.get('valid', len(examples)))}")
        else:
            examples = curated_data if isinstance(curated_data, list) else []
        
        curated_added = 0
        for example in examples:
            code = example.get("vulnerable_code", "").strip()
            code_hash = hash(code)
            
            if len(code) > 20 and code_hash not in seen_codes:
                seen_codes.add(code_hash)
                vulnerable_examples.append({
                    "code": code,
                    "label": 1,
                    "advisory_id": example.get("id", "unknown"),
                    "cwe_id": example.get("cwe_id", ""),
                    "severity": example.get("severity", "MEDIUM"),
                    "quality_score": example.get("quality_score", 0.7),
                    "source": example.get("source", "curated"),
                    "has_fix": bool(example.get("fixed_code"))
                })
                curated_added += 1
        
        print(f"✓ Added {curated_added} additional curated examples")
    
    print(f"\n📈 Total vulnerable examples: {len(vulnerable_examples)}")
    
    if len(vulnerable_examples) == 0:
        print("⚠️  WARNING: No vulnerable examples found!")
        print("   Run: python run_pipeline.py --step preprocess")
        raise ValueError("No vulnerable examples found!")
    
    return vulnerable_examples


def stream_codesearchnet_examples(
    codesearchnet_dir: str, max_examples: int
) -> Iterator[Dict[str, Any]]:
    """
    Streams safe code examples from the CodeSearchNet dataset directory.
    
    CodeSearchNet contains open-source Python code that we assume is safe
    (not containing known vulnerabilities). This provides negative examples
    for training the vulnerability detection model.

    This function reads through the JSONL files in the specified directory
    and yields safe code examples up to a defined maximum.

    Args:
        codesearchnet_dir: The directory containing CodeSearchNet .jsonl files.
        max_examples: The maximum number of safe examples to load.

    Yields:
        A dictionary representing a safe code example with label 0 (safe).
    """
    print("Streaming safe examples from CodeSearchNet...")
    count = 0
    jsonl_files = [f for f in os.listdir(codesearchnet_dir) if f.endswith(".jsonl")]

    for file_name in tqdm(jsonl_files, desc="Processing CodeSearchNet files"):
        if count >= max_examples:
            break
        file_path = os.path.join(codesearchnet_dir, file_name)
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                if count >= max_examples:
                    break
                try:
                    data = json.loads(line)
                    # Use 'original_string' which contains the full function code
                    if "original_string" in data and data["original_string"]:
                        code = data["original_string"].strip()
                        
                        # Filter out very short code snippets
                        if len(code) > 20:
                            yield {
                                "code": code,
                                "label": 0,  # 0 = safe (no known vulnerabilities)
                                "repo": data.get("repo", ""),
                                "path": data.get("path", "")
                            }
                            count += 1
                except (json.JSONDecodeError, KeyError):
                    continue
    
    print(f"Loaded {count} safe code examples from CodeSearchNet")


def create_dataset(config: Dict[str, Any]):
    """
    Main function to create and save the massive dataset.

    Args:
        config: A dictionary containing the configuration parameters, typically
                loaded from a YAML file.
    """
    print("\n" + "="*60)
    print("🎯 CREATING GRAPH DATASET FROM HIGH-QUALITY DATA")
    print("="*60)
    
    # Determine which vulnerable data source to use
    use_curated = config["data"].get("sources", {}).get("use_curated_vulnerabilities", True)
    curated_path = config["data"].get("validated_dataset_path")
    
    # Load vulnerable examples (curated if available, else legacy)
    vulnerable_examples = load_vulnerable_examples(
        advisories_path=config["data"]["advisories_path"],
        use_curated=use_curated,
        curated_path=curated_path
    )
    
    # Add synthetic vulnerable examples for better pattern coverage
    if config["data"]["sources"].get("synthetic", True):
        try:
            from data_processing.synthetic_vulnerabilities import generate_synthetic_vulnerabilities, generate_simple_safe_examples
            
            synthetic_count = config["dataset"].get("diversity", {}).get("synthetic_count", 200)
            print(f"\n🔧 Adding {synthetic_count} synthetic vulnerability examples per category...")
            
            synthetic_examples = generate_synthetic_vulnerabilities(
                num_per_category=synthetic_count // 7,  # ~7 vulnerability categories
                include_safe=False  # Only add vulnerable examples here
            )
            
            # Convert to our format
            for syn_ex in synthetic_examples:
                vulnerable_examples.append({
                    "code": syn_ex["code"],
                    "label": 1,
                    "advisory_id": f"synthetic_{syn_ex['category']}",
                    "cwe_id": syn_ex.get("cwe", ""),
                    "severity": "MEDIUM",
                    "quality_score": 1.0,  # Synthetic = perfect quality
                    "source": "synthetic"
                })
            
            print(f"✓ Added {len(synthetic_examples)} synthetic vulnerable examples")
            
            # Count by category
            from collections import Counter
            categories = Counter(ex.get("category", "unknown") for ex in synthetic_examples)
            print("   Categories:", dict(categories))
            
            # Also add SIMPLE SAFE examples - critical for avoiding false positives
            simple_safe_count = config["dataset"].get("diversity", {}).get("simple_safe_count", 500)
            print(f"\n🛡️ Adding {simple_safe_count} simple safe code examples...")
            
            simple_safe_examples = generate_simple_safe_examples(count=simple_safe_count)
            
            # These go into safe_examples later, but we track them separately
            print(f"✓ Generated {len(simple_safe_examples)} simple safe examples")
            safe_categories = Counter(ex.get("category", "unknown") for ex in simple_safe_examples)
            print("   Categories:", dict(safe_categories))
            
        except ImportError as e:
            print(f"⚠️  Could not load synthetic vulnerabilities: {e}")
            simple_safe_examples = []
    else:
        simple_safe_examples = []

    # Stream and process safe examples from CodeSearchNet
    if config["data"]["sources"].get("codesearchnet", True):
        safe_examples_stream = stream_codesearchnet_examples(
            config["data"]["codesearchnet_dir"], config["dataset"]["max_safe_examples"]
        )
        safe_examples = list(safe_examples_stream)
    else:
        print("⚠️  CodeSearchNet disabled in config - no safe examples loaded")
        safe_examples = []
    
    # Add synthetic simple safe examples (critical for avoiding false positives on simple code)
    if simple_safe_examples:
        for syn_safe in simple_safe_examples:
            safe_examples.append({
                "code": syn_safe["code"],
                "label": 0,  # Safe
                "repo": "synthetic",
                "path": syn_safe.get("category", "simple_safe"),
                "source": "synthetic_safe",
                "quality_score": syn_safe.get("quality_score", 1.0)
            })
        print(f"✓ Added {len(simple_safe_examples)} synthetic safe examples to safe pool")

    all_examples = vulnerable_examples + safe_examples
    
    print(f"\n📊 Dataset Composition (Before Conversion):")
    print(f"   Vulnerable: {len(vulnerable_examples)}")
    print(f"   Safe: {len(safe_examples)}")
    print(f"   Total: {len(all_examples)}")
    print(f"   Ratio: 1:{len(safe_examples)//len(vulnerable_examples) if vulnerable_examples else 0}")

    # Convert all examples to graphs with detailed tracking
    print(f"\n🔄 Converting {len(all_examples)} code examples to graphs...")
    graph_dataset = []
    
    # Track conversion stats separately for vulnerable and safe
    vuln_success = 0
    vuln_fail = 0
    safe_success = 0
    safe_fail = 0
    
    for example in tqdm(all_examples, desc="Converting code to graphs"):
        pyg_graph = code_to_pyg_graph(
            code=example["code"],
            label=example["label"],
            max_nodes=config["dataset"]["max_nodes_per_graph"],
            num_node_features=config["model"]["num_node_features"],
        )
        if pyg_graph:
            graph_dataset.append(pyg_graph)
            if example["label"] == 1:
                vuln_success += 1
            else:
                safe_success += 1
        else:
            if example["label"] == 1:
                vuln_fail += 1
            else:
                safe_fail += 1

    # Calculate conversion rates
    vuln_total = vuln_success + vuln_fail
    safe_total = safe_success + safe_fail
    total_success = vuln_success + safe_success
    total_fail = vuln_fail + safe_fail
    total = total_success + total_fail
    
    # Print detailed conversion statistics
    print(f"\n" + "="*60)
    print("📈 CONVERSION STATISTICS")
    print("="*60)
    
    print(f"\n🔴 Vulnerable Examples:")
    print(f"   Input:      {vuln_total:,}")
    print(f"   Converted:  {vuln_success:,}")
    print(f"   Failed:     {vuln_fail:,}")
    print(f"   Success Rate: {100*vuln_success/vuln_total:.1f}%" if vuln_total > 0 else "   Success Rate: N/A")
    
    print(f"\n🟢 Safe Examples:")
    print(f"   Input:      {safe_total:,}")
    print(f"   Converted:  {safe_success:,}")
    print(f"   Failed:     {safe_fail:,}")
    print(f"   Success Rate: {100*safe_success/safe_total:.1f}%" if safe_total > 0 else "   Success Rate: N/A")
    
    print(f"\n📊 Total:")
    print(f"   Input:      {total:,}")
    print(f"   Converted:  {total_success:,}")
    print(f"   Failed:     {total_fail:,}")
    print(f"   Success Rate: {100*total_success/total:.1f}%" if total > 0 else "   Success Rate: N/A")
    
    # Final dataset composition
    print(f"\n" + "="*60)
    print("📦 FINAL DATASET COMPOSITION")
    print("="*60)
    print(f"   Vulnerable graphs: {vuln_success:,}")
    print(f"   Safe graphs:       {safe_success:,}")
    print(f"   Total graphs:      {total_success:,}")
    if vuln_success > 0:
        print(f"   Final Ratio:       1:{safe_success/vuln_success:.1f} (vulnerable:safe)")
    
    # Save the final dataset
    output_path = config["data"]["processed_dataset_path"]
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    print(f"\n💾 Saving {len(graph_dataset)} graphs to {output_path}...")
    torch.save(graph_dataset, output_path)
    
    # Save conversion stats to JSON for tracking
    stats = {
        "vulnerable": {
            "input": vuln_total,
            "converted": vuln_success,
            "failed": vuln_fail,
            "success_rate": round(100*vuln_success/vuln_total, 2) if vuln_total > 0 else 0
        },
        "safe": {
            "input": safe_total,
            "converted": safe_success,
            "failed": safe_fail,
            "success_rate": round(100*safe_success/safe_total, 2) if safe_total > 0 else 0
        },
        "total": {
            "input": total,
            "converted": total_success,
            "failed": total_fail,
            "success_rate": round(100*total_success/total, 2) if total > 0 else 0
        },
        "final_ratio": round(safe_success/vuln_success, 2) if vuln_success > 0 else 0
    }
    
    stats_path = output_path.replace(".pt", "_stats.json")
    with open(stats_path, "w") as f:
        json.dump(stats, f, indent=2)
    print(f"📊 Conversion stats saved to {stats_path}")
    
    print(f"\n✅ Dataset Creation Complete!")
    print("="*60)


if __name__ == "__main__":
    import yaml

    # This allows the script to be run standalone for data creation.
    # In a production pipeline, you would import `create_dataset` and call it.
    print("Running dataset creation as a standalone script.")
    with open("configs/base_config.yaml", "r") as f:
        config = yaml.safe_load(f)
    create_dataset(config)
