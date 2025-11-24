# GNN-Based Vulnerability Detection in Python Code

## Project Overview

This project provides a framework for training a Graph Neural Network (GNN) to detect security vulnerabilities in Python source code. It leverages real-world vulnerability data from the GitHub Security Advisory database and safe code examples from the CodeSearchNet dataset.

The entire pipeline, from data processing to model training, is designed to be reproducible and is managed via a central configuration file.

## Features

- **End-to-End Pipeline**: Scripts for data creation, training, and evaluation.
- **Graph-Based Learning**: Converts code into Abstract Syntax Trees (ASTs) for structural analysis with a GNN.
- **Large-Scale Training**: Optimized for datasets with over 200,000 examples.
- **Class Imbalance Handling**: Uses weighted loss to prioritize the detection of the minority (vulnerable) class.
- **Reproducibility**: A single `config.yaml` file controls all parameters and paths.
- **Progress Tracking**: Real-time `tqdm` progress bars for monitoring training.
- **MLflow Integration**: Automatic experiment tracking, model versioning, and metrics logging.

## Project Structure

```
/GNN_project
├── configs/
│   └── base_config.yaml      # Central configuration for all parameters
├── data/
│   └── ...                   # Raw data (advisory database, CodeSearchNet)
├── docs/
│   └── ...                   # Project documentation and progress reports
├── outputs/
│   ├── datasets/             # Generated datasets (.pt, .json files)
│   ├── models/               # Trained model weights
│   └── results/              # Evaluation results and visualizations
├── src/
│   ├── preprocess_advisories.py   # Extract vulnerable code from GitHub
│   ├── create_dataset.py          # Convert code to graph dataset
│   ├── train_model.py             # Train GNN model
│   ├── evaluate_model.py          # Evaluate trained model
│   ├── filter_python_advisories.py # Filter PyPI advisories
│   ├── data_processing/           # Graph conversion utilities
│   ├── modeling/                  # GNN model definition
│   └── training/                  # Training utilities
├── .gitignore
├── README.md
├── requirements.txt
└── run_pipeline.py           # Main entry point for the pipeline
```

## Getting Started

### 1. Setup

**Prerequisites:**
- Python 3.9+
- `git` (for cloning advisory data)

**Installation:**

First, clone the GitHub Security Advisory database into the project root. This will be used as the source for vulnerable code examples.
```bash
git clone https://github.com/github/advisory-database.git
```

Next, create a virtual environment and install the required packages:
```bash
python -m venv venv
source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
pip install -r requirements.txt
```

### 2. Configuration

All parameters for data paths, model architecture, and training are controlled by `configs/base_config.yaml`. Before running, review this file and adjust paths or hyperparameters as needed.

Key settings to check:
- `data.advisories_path`: Path to the advisory data.
- `data.codesearchnet_dir`: Path to the directory containing CodeSearchNet `.jsonl` files.
- `training.device`: Set to `auto`, `cuda`, or `cpu`.

### 3. Running the Pipeline

The pipeline is executed through the scripts in the `scripts/` directory.

**Step 0: Preprocess GitHub Advisories (REQUIRED)**

This script extracts actual vulnerable Python code from GitHub commits referenced in the Security Advisory database. It fetches commit data via the GitHub API and parses git diffs to extract vulnerable code snippets.

```bash
python src/preprocess_advisories.py
```

**Important:** Set the `GITHUB_PAT` environment variable with a GitHub Personal Access Token to increase rate limits from 60 to 5000 requests/hour:
```bash
# Windows (Command Prompt)
set GITHUB_PAT=your_token_here

# Windows (PowerShell)
$env:GITHUB_PAT="your_token_here"
```

This will create `outputs/datasets/processed_advisories_with_code.json` containing vulnerable code examples.

**Step 1: Create the Dataset**

This script will process the preprocessed advisories and CodeSearchNet data, convert code to graphs, and save a single `final_graph_dataset.pt` file.
```bash
python src/create_dataset.py
```

**Step 2: Train the Model**

This script loads the processed dataset, splits it, calculates class weights, and runs the training and evaluation loop. The final trained model will be saved with MLflow tracking enabled.
```bash
python src/train_model.py
```

After training, the console will display the final test set metrics, and the trained model will be saved to the path specified in `output.model_save_path` in the config file.

### Viewing Experiment Results with MLflow

The project automatically tracks all training runs with MLflow. To view results:

```bash
python view_mlflow.py
```

Then open http://localhost:5000 in your browser to:
- Compare different experiments
- View training curves and metrics
- Access logged models and artifacts
- Track hyperparameter performance

See `docs/MLFLOW_GUIDE.md` for detailed MLflow usage.

## Model Architecture

The model (`VulnerabilityGNN`) is a Graph Neural Network that includes:
- **Graph Convolutional Network (GCN)** layers for message passing.
- A **Graph Attention (GAT)** layer to focus on important nodes.
- A final MLP head for binary classification (vulnerable/safe).

The architecture is defined in `src/modeling/model.py` and is configurable via `configs/base_config.yaml`.

