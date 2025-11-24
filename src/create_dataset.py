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
    Loads vulnerable code examples from advisories or curated dataset.
    
    This function can load from two sources:
    1. Curated dataset (default) - High-quality, validated examples from data curation
    2. Raw processed advisories - Legacy format for backward compatibility

    Args:
        advisories_path: Path to the processed advisories JSON file (legacy).
        use_curated: If True, attempts to load from curated dataset first.
        curated_path: Path to curated/validated dataset JSON file.

    Returns:
        A list of dictionaries, where each dictionary represents a vulnerable
        code snippet with actual Python code.
    """
    vulnerable_examples = []
    
    # Try loading from curated dataset first (higher quality)
    if use_curated and curated_path and os.path.exists(curated_path):
        print(f"Loading HIGH-QUALITY curated vulnerable examples from {curated_path}...")
        
        with open(curated_path, "r", encoding="utf-8") as f:
            curated_data = json.load(f)
        
        # Handle new curated format with metadata
        if "examples" in curated_data:
            examples = curated_data["examples"]
            stats = curated_data.get("statistics", {})
            
            print(f"📊 Curated Dataset Statistics:")
            print(f"   Total examples: {stats.get('total_examples', len(examples))}")
            print(f"   Avg quality score: {stats.get('avg_quality_score', 0):.3f}")
            print(f"   Examples with fixes: {stats.get('has_fixes', 0)}")
            print(f"   Unique CWE types: {stats.get('cwe_types', 0)}")
        else:
            examples = curated_data
        
        for example in examples:
            code = example.get("vulnerable_code", "").strip()
            
            if len(code) > 20:
                vulnerable_examples.append({
                    "code": code,
                    "label": 1,  # 1 = vulnerable
                    "advisory_id": example.get("id", "unknown"),
                    "cwe_id": example.get("cwe_id", ""),
                    "severity": example.get("severity", "MEDIUM"),
                    "quality_score": example.get("quality_score", 0.0),
                    "source": example.get("source", "curated"),
                    "has_fix": bool(example.get("fixed_code"))
                })
        
        print(f"✓ Loaded {len(vulnerable_examples)} curated vulnerable examples")
        
        # Show quality distribution
        if vulnerable_examples:
            avg_quality = sum(ex.get("quality_score", 0) for ex in vulnerable_examples) / len(vulnerable_examples)
            with_fixes = sum(1 for ex in vulnerable_examples if ex.get("has_fix"))
            print(f"   Average quality: {avg_quality:.3f}")
            print(f"   With fixes: {with_fixes}/{len(vulnerable_examples)} ({100*with_fixes/len(vulnerable_examples):.1f}%)")
        
        return vulnerable_examples
    
    # Fallback to legacy format
    print("Loading vulnerable examples from processed advisories (legacy format)...")
    
    if not os.path.exists(advisories_path):
        print(f"❌ Error: {advisories_path} not found!")
        print(f"Please run one of:")
        print(f"  1. python src/run_data_curation.py (recommended - high quality)")
        print(f"  2. python run_pipeline.py --step preprocess (legacy)")
        raise FileNotFoundError(f"Advisories not found: {advisories_path}")
    
    with open(advisories_path, "r", encoding="utf-8") as f:
        advisories = json.load(f)

    for advisory in advisories:
        # Use actual vulnerable code extracted from commits
        if "vulnerable_code" in advisory and advisory["vulnerable_code"]:
            code = advisory["vulnerable_code"].strip()
            
            # Filter out examples that are too short (likely not useful)
            if len(code) > 20:
                vulnerable_examples.append({
                    "code": code,
                    "label": 1,  # 1 = vulnerable
                    "advisory_id": advisory.get("advisory_id", ""),
                    "filename": advisory.get("filename", ""),
                    "severity": "UNKNOWN",  # Legacy format doesn't have proper severity
                    "quality_score": 0.5,  # Default for legacy data
                    "source": "legacy"
                })
    
    print(f"Found {len(vulnerable_examples)} vulnerable code examples (legacy)")
    
    if len(vulnerable_examples) == 0:
        print("⚠️  WARNING: No vulnerable examples found!")
        print("   Run: python src/run_data_curation.py")
    
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

    # Stream and process safe examples from CodeSearchNet
    if config["data"]["sources"].get("codesearchnet", True):
        safe_examples_stream = stream_codesearchnet_examples(
            config["data"]["codesearchnet_dir"], config["dataset"]["max_safe_examples"]
        )
        safe_examples = list(safe_examples_stream)
    else:
        print("⚠️  CodeSearchNet disabled in config - no safe examples loaded")
        safe_examples = []

    all_examples = vulnerable_examples + safe_examples
    
    print(f"\n📊 Dataset Composition:")
    print(f"   Vulnerable: {len(vulnerable_examples)}")
    print(f"   Safe: {len(safe_examples)}")
    print(f"   Total: {len(all_examples)}")
    print(f"   Ratio: 1:{len(safe_examples)//len(vulnerable_examples) if vulnerable_examples else 0}")

    # Convert all examples to graphs
    print(f"\n🔄 Converting {len(all_examples)} code examples to graphs...")
    graph_dataset = []
    failed_conversions = 0
    
    for example in tqdm(all_examples, desc="Converting code to graphs"):
        pyg_graph = code_to_pyg_graph(
            code=example["code"],
            label=example["label"],
            max_nodes=config["dataset"]["max_nodes_per_graph"],
            num_node_features=config["model"]["num_node_features"],
        )
        if pyg_graph:
            graph_dataset.append(pyg_graph)
        else:
            failed_conversions += 1

    # Save the final dataset
    output_path = config["data"]["processed_dataset_path"]
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    print(f"\n💾 Saving {len(graph_dataset)} graphs to {output_path}...")
    torch.save(graph_dataset, output_path)
    
    print(f"\n✅ Dataset Creation Complete!")
    print(f"   Successfully converted: {len(graph_dataset)} graphs")
    print(f"   Failed conversions: {failed_conversions} ({100*failed_conversions/len(all_examples):.1f}%)")
    print(f"   Output: {output_path}")
    print("="*60)


if __name__ == "__main__":
    import yaml

    # This allows the script to be run standalone for data creation.
    # In a production pipeline, you would import `create_dataset` and call it.
    print("Running dataset creation as a standalone script.")
    with open("configs/base_config.yaml", "r") as f:
        config = yaml.safe_load(f)
    create_dataset(config)
