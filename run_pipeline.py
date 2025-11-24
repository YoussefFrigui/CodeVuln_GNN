#!/usr/bin/env python3
"""
GNN Vulnerability Detection Pipeline
Main orchestrator script for the complete ML pipeline
"""

import os
import sys
import subprocess
import argparse
from pathlib import Path

def run_script(script_name, description, extra_args=''):
    """Run a Python script and handle errors."""
    script_path = f"src/{script_name}"
    
    # Use unbuffered Python to ensure real-time output
    cmd = f"python -u {script_path}"
    if extra_args:
        cmd += f" {extra_args}"

    print(f"\n{'='*50}")
    print(f"Running: {description}")
    print(f"Command: {cmd}")
    print(f"{'='*50}\n")

    try:
        # Run without capturing output to allow real-time progress bars
        result = subprocess.run(cmd, shell=True, check=True)
        print(f"\n✓ {description} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"\n✗ {description} failed with exit code {e.returncode}")
        return False

def check_dependencies():
    """Check if required packages are installed."""
    required_packages = [
        'torch', 'torch_geometric', 'networkx',
        'matplotlib', 'seaborn', 'sklearn', 'tqdm', 'yaml', 'mlflow'
    ]

    missing_packages = []
    for package in required_packages:
        try:
            __import__(package.replace('-', '_'))
        except ImportError:
            missing_packages.append(package)

    if missing_packages:
        print("Missing required packages:", ', '.join(missing_packages))
        print("Please install them using:")
        print(f"pip install {' '.join(missing_packages)}")
        return False

    print("✓ All required packages are installed")
    return True

def check_data_files(step):
    """Check if required data files exist for the given step."""
    if step == 'filter':
        required_files = []  # No prerequisites for filtering
    elif step == 'preprocess':
        required_files = ['outputs/datasets/python_advisories.json']
    elif step == 'curate':
        required_files = ['outputs/datasets/processed_advisories_with_code.json']
    elif step == 'dataset':
        # Can work with either curated or processed advisories
        curated_exists = os.path.exists('outputs/datasets/validated_vulnerabilities.json')
        processed_exists = os.path.exists('outputs/datasets/processed_advisories_with_code.json')
        if not curated_exists and not processed_exists:
            print("Missing required data files:")
            print("  - outputs/datasets/validated_vulnerabilities.json (curated - recommended)")
            print("  - outputs/datasets/processed_advisories_with_code.json (legacy)")
            print("\nPlease run: python src/run_data_curation.py (recommended)")
            print("       or: python run_pipeline.py --step preprocess (legacy)")
            return False
        required_files = []
    elif step in ['train', 'evaluate', 'all']:
        required_files = ['outputs/datasets/final_graph_dataset.pt']
        if step == 'evaluate':
            required_files.append('outputs/models/trained_gnn_model.pt')
    else:
        required_files = []

    missing_files = []
    for file_path in required_files:
        if not os.path.exists(file_path):
            missing_files.append(file_path)

    if missing_files:
        print("Missing required data files:")
        for file in missing_files:
            print(f"  - {file}")
        if step == 'preprocess':
            print("\nPlease run filter step first: python run_pipeline.py --step filter")
        elif step == 'curate':
            print("\nPlease run preprocessing first: python run_pipeline.py --step preprocess")
        elif step == 'dataset':
            print("\nPlease run data curation first: python src/run_data_curation.py")
        elif step == 'train':
            print("\nPlease run dataset creation first: python run_pipeline.py --step dataset")
        elif step == 'evaluate':
            print("\nPlease run training first: python run_pipeline.py --step train")
        return False

    print("✓ All required data files are present")
    return True

def main():
    parser = argparse.ArgumentParser(description='GNN Vulnerability Detection Pipeline')
    parser.add_argument('--step', choices=['filter', 'preprocess', 'curate', 'dataset', 'train', 'evaluate', 'all'],
                       default='all', help='Which step to run (default: all)')
    parser.add_argument('--skip-checks', action='store_true',
                       help='Skip dependency and data file checks')

    args = parser.parse_args()

    print("GNN Vulnerability Detection Pipeline")
    print("=" * 50)

    # Initial checks
    if not args.skip_checks:
        if not check_dependencies():
            return 1
        if not check_data_files(args.step):
            return 1

    success = True

    # Step 0: Filter Python Advisories
    if args.step in ['filter', 'all']:
        if not run_script('filter_python_advisories.py', 'Step 0: Filter Python Advisories'):
            success = False
            if args.step != 'all':
                return 1

    # Step 1: Preprocess Advisories (Extract Vulnerable Code)
    if args.step in ['preprocess', 'all']:
        if not run_script('preprocess_advisories.py', 'Step 1: Extract Vulnerable Code from GitHub'):
            success = False
            if args.step != 'all':
                return 1

    # Step 1.5: Curate High-Quality Dataset (NEW - Recommended)
    if args.step in ['curate', 'all']:
        if not run_script('run_data_curation.py', 'Step 1.5: Curate High-Quality Dataset'):
            success = False
            if args.step != 'all':
                return 1

    # Step 2: Create Graph Dataset
    if args.step in ['dataset', 'all']:
        if not run_script('create_dataset.py', 'Step 2: Create Graph Dataset'):
            success = False
            if args.step != 'all':
                return 1

    # Step 3: Train GNN Model
    if args.step in ['train', 'all']:
        if not run_script('train_model.py', 'Step 3: Train GNN Model'):
            success = False
            if args.step != 'all':
                return 1

    # Step 4: Evaluate Model
    if args.step in ['evaluate', 'all']:
        if not run_script('evaluate_model.py', 'Step 4: Evaluate Model'):
            success = False
            if args.step != 'all':
                return 1

    if success:
        print(f"\n{'='*50}")
        print("🎉 Pipeline completed successfully!")
        print("Check the generated files:")
        print("  - outputs/datasets/python_advisories.json (filtered advisories)")
        print("  - outputs/datasets/processed_advisories_with_code.json (vulnerable code)")
        print("  - outputs/datasets/curated_vulnerabilities.json (curated dataset)")
        print("  - outputs/datasets/validated_vulnerabilities.json (validated dataset)")
        print("  - outputs/datasets/final_graph_dataset.pt (graph dataset)")
        print("  - outputs/models/trained_gnn_model.pt (trained model)")
        print("  - outputs/results/confusion_matrix.png (evaluation plot)")
        print(f"{'='*50}")
        return 0
    else:
        print(f"\n{'='*50}")
        print("❌ Pipeline failed. Check the error messages above.")
        print(f"{'='*50}")
        return 1

if __name__ == '__main__':
    sys.exit(main())