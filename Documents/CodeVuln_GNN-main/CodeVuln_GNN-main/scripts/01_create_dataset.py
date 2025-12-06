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

from src.data_processing.graph_utils import code_to_pyg_graph


def load_vulnerable_examples(advisories_path: str) -> List[Dict[str, Any]]:
    """
    Loads vulnerable code examples from the processed advisories JSON file.

    Args:
        advisories_path: Path to the JSON file containing advisory data.

    Returns:
        A list of dictionaries, where each dictionary represents a vulnerable
        code snippet.
    """
    print("Loading vulnerable examples from advisories...")
    with open(advisories_path, "r", encoding="utf-8") as f:
        advisories = json.load(f)

    vulnerable_examples = []
    for advisory in advisories:
        if "vulnerable_code" in advisory and advisory["vulnerable_code"]:
            vulnerable_examples.append(
                {"code": advisory["vulnerable_code"], "label": 1}
            )
    print(f"Found {len(vulnerable_examples)} vulnerable examples.")
    return vulnerable_examples


def stream_codesearchnet_examples(
    codesearchnet_dir: str, max_examples: int
) -> Iterator[Dict[str, Any]]:
    """
    Streams safe code examples from the CodeSearchNet dataset directory.

    This function reads through the JSONL files in the specified directory
    and yields safe code examples up to a defined maximum.

    Args:
        codesearchnet_dir: The directory containing CodeSearchNet .jsonl files.
        max_examples: The maximum number of safe examples to load.

    Yields:
        A dictionary representing a safe code example.
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
                        yield {"code": data["original_string"], "label": 0}
                        count += 1
                except (json.JSONDecodeError, KeyError):
                    continue


def create_dataset(config: Dict[str, Any]):
    """
    Main function to create and save the massive dataset.

    Args:
        config: A dictionary containing the configuration parameters, typically
                loaded from a YAML file.
    """
    # Load vulnerable examples
    vulnerable_examples = load_vulnerable_examples(config["data"]["advisories_path"])

    # Stream and process safe examples
    safe_examples_stream = stream_codesearchnet_examples(
        config["data"]["codesearchnet_dir"], config["dataset"]["max_safe_examples"]
    )

    all_examples = vulnerable_examples + list(safe_examples_stream)
    print(f"Total examples to process: {len(all_examples)}")

    # Convert all examples to graphs
    graph_dataset = []
    for example in tqdm(all_examples, desc="Converting code to graphs"):
        pyg_graph = code_to_pyg_graph(
            code=example["code"],
            label=example["label"],
            max_nodes=config["dataset"]["max_nodes_per_graph"],
            num_node_features=config["model"]["num_node_features"],
        )
        if pyg_graph:
            graph_dataset.append(pyg_graph)

    # Save the final dataset
    output_path = config["data"]["processed_dataset_path"]
    print(f"Saving {len(graph_dataset)} graphs to {output_path}...")
    torch.save(graph_dataset, output_path)
    print("Dataset creation complete.")


if __name__ == "__main__":
    import yaml

    # This allows the script to be run standalone for data creation.
    # In a production pipeline, you would import `create_dataset` and call it.
    print("Running dataset creation as a standalone script.")
    with open("configs/base_config.yaml", "r") as f:
        config = yaml.safe_load(f)
    create_dataset(config)
