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
    cmd = f"python {script_path}"
    if extra_args:
        cmd += f" {extra_args}"

    print(f"\n{'='*50}")
    print(f"Running: {description}")
    print(f"Command: {cmd}")
    print(f"{'='*50}")

    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True)
        print(result.stdout)
        if result.stderr:
            print("Warnings/Errors:", result.stderr)
        print(f"✓ {description} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"✗ {description} failed with exit code {e.returncode}")
        print("STDOUT:", e.stdout)
        print("STDERR:", e.stderr)
        return False

def check_dependencies():
    """Check if required packages are installed."""
    required_packages = [
        'torch', 'torch_geometric', 'networkx',
        'transformers', 'matplotlib', 'seaborn', 'sklearn'
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
    if step == 'preprocess':
        required_files = ['outputs/datasets/labeled_dataset.json']
    elif step in ['train', 'evaluate', 'all']:
        required_files = ['outputs/datasets/processed_graphs.pt', 'outputs/datasets/data_splits.pt']
        if step == 'evaluate':
            required_files.append('outputs/models/vulnerability_gnn_model.pt')
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
            print("\nPlease ensure you have completed the data pipeline steps first.")
        elif step == 'train':
            print("\nPlease run preprocessing first: python run_pipeline.py --step preprocess")
        elif step == 'evaluate':
            print("\nPlease run preprocessing and training first.")
        return False

    print("✓ All required data files are present")
    return True

def main():
    parser = argparse.ArgumentParser(description='GNN Vulnerability Detection Pipeline')
    parser.add_argument('--step', choices=['preprocess', 'train', 'evaluate', 'all'],
                       default='all', help='Which step to run (default: all)')
    parser.add_argument('--dataset', choices=['original', 'expanded'],
                       default='original', help='Which dataset to use (default: original)')
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

    # Step 1: Data Preprocessing
    if args.step in ['preprocess', 'all']:
        if not run_script('preprocess_data.py', 'Data Preprocessing', f'--dataset {args.dataset}'):
            success = False
            if args.step != 'all':
                return 1

    # Step 2: Model Training
    if args.step in ['train', 'all']:
        if not run_script('train_gnn.py', 'GNN Model Training'):
            success = False
            if args.step != 'all':
                return 1

    # Step 3: Model Evaluation
    if args.step in ['evaluate', 'all']:
        if not run_script('evaluate_model.py', 'Model Evaluation'):
            success = False
            if args.step != 'all':
                return 1

    if success:
        print(f"\n{'='*50}")
        print("🎉 Pipeline completed successfully!")
        print("Check the generated files:")
        print("  - outputs/datasets/processed_graphs.pt (preprocessed data)")
        print("  - outputs/models/vulnerability_gnn_model.pt (trained model)")
        print("  - confusion_matrix.png (evaluation plot)")
        print(f"{'='*50}")
        return 0
    else:
        print(f"\n{'='*50}")
        print("❌ Pipeline failed. Check the error messages above.")
        print(f"{'='*50}")
        return 1

if __name__ == '__main__':
    sys.exit(main())
