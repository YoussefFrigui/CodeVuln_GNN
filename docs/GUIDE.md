# GNN Vulnerability Detection - Collaborator Setup Guide

This guide will help you set up the project locally and obtain the necessary data files that are excluded from the Git repository.

---

## **Quick Start**

### **1. Clone the Repository**

```bash
git clone https://github.com/YoussefFrigui/CodeVuln_GNN.git
cd CodeVuln_GNN
```

### **2. Set Up Python Environment**

**Prerequisites:**
- Python 3.9 or higher
- Git (for cloning the repository and submodules)
- 16+ GB RAM recommended for data processing
- GPU with CUDA support (optional, but recommended for faster training)

**Installation:**

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# If you have a GPU, install PyTorch with CUDA support:
# Visit https://pytorch.org/get-started/locally/ for the correct command
# Example for CUDA 11.8:
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu118
```

**Additional Dependency:**

The scripts use YAML for configuration. Ensure `pyyaml` is installed:

```bash
pip install pyyaml
```

---

## **3. Obtaining Required Data**

The following data sources are required to run the project. All data files are **excluded from Git** and must be downloaded separately.

---

### **Step 1: Download CodeSearchNet Python Dataset**

**Source:** [Kaggle - CodeSearchNet](https://www.kaggle.com/datasets/omduggineni/codesearchnet?select=python)

#### **Option A: Download via Kaggle Web Interface**

1. Visit: https://www.kaggle.com/datasets/omduggineni/codesearchnet?select=python
2. Click the **"Download"** button (you may need to create a free Kaggle account)
3. Extract the downloaded ZIP file
4. Copy the `python/` folder to your project's `data/` directory:
   ```
   GNN_project/
   └── data/
       └── python/
   ```

#### **Option B: Download via Kaggle CLI (Recommended)**

```bash
# Install Kaggle CLI
pip install kaggle

# Set up Kaggle API credentials
# 1. Go to: https://www.kaggle.com/settings
# 2. Scroll to "API" section and click "Create New API Token"
# 3. This downloads kaggle.json - place it in:
#    Windows: C:\Users\<YourUsername>\.kaggle\kaggle.json
#    Linux/Mac: ~/.kaggle/kaggle.json

# Download the dataset
kaggle datasets download -d omduggineni/codesearchnet

# Extract to data directory
unzip codesearchnet.zip -d data/

# Or on Windows PowerShell:
Expand-Archive -Path codesearchnet.zip -DestinationPath data/
```

---

### **Step 2: Download GitHub Advisory Database**

**Source:** [GitHub Advisory Database](https://github.com/github/advisory-database)

```bash
# Clone as a git submodule
git submodule add https://github.com/github/advisory-database.git data/advisory-database
git submodule update --init --recursive

# Or clone directly
git clone https://github.com/github/advisory-database.git data/advisory-database
```

---

### **Step 3: Generate Processed Dataset Files**

Once you have the raw data, run the pipeline to generate all required files:

```bash
# Run the full data processing pipeline
python run_pipeline.py
```

This will create:
- `final_graph_dataset.pt` (~962 MB) - Processed training dataset
- `labeled_dataset.json` - Labeled vulnerability data
- `python_advisories.json` - Filtered Python security advisories
- `commit_data_results.json` - GitHub commit analysis
- Other intermediate files

**⚠️ Warning:** This process can take **several hours** and requires significant computational resources (16+ GB RAM recommended).

---

### **Step 4: Configure the Project**

Before running the pipeline, review and customize the configuration file:

**File:** `configs/base_config.yaml`

Key settings to verify/adjust:

```yaml
data:
  advisories_path: "github_advisories.json"  # Path to filtered Python advisories
  codesearchnet_dir: "data/python/python/final/jsonl/train"  # CodeSearchNet data location
  processed_dataset_path: "final_graph_dataset.pt"  # Output processed dataset

dataset:
  max_safe_examples: 200000  # Number of safe code examples to use
  max_nodes_per_graph: 100   # Maximum AST nodes per code snippet

model:
  num_node_features: 11      # AST node feature vector size
  hidden_channels: 128       # GNN hidden layer size
  gcn_layers: 4              # Number of GCN layers
  gat_heads: 8               # Number of attention heads

training:
  device: "auto"             # Use "cuda" if available, else "cpu"
  num_epochs: 20
  batch_size: 64
  learning_rate: 0.001
  patience: 5                # Early stopping patience
```

**💡 Tip:** For faster experimentation, reduce `max_safe_examples` to 50,000 or lower.

---

## **5. Running the Project**

### **Option A: Run Individual Scripts**

#### **Train the Model:**

```bash
python scripts/02_train_model.py
```

#### **Evaluate the Model:**

```bash
python src/evaluate_model.py
```

### **Option B: Run Full Pipeline (Recommended for First-Time Setup)**

The `run_pipeline.py` orchestrator script manages the complete workflow:

```bash
# Run all steps (preprocessing, training, evaluation)
python run_pipeline.py --step all

# Or run specific steps:
python run_pipeline.py --step preprocess  # Data processing only
python run_pipeline.py --step train       # Training only
python run_pipeline.py --step evaluate    # Evaluation only
```

**Expected Outputs:**
- `final_graph_dataset.pt` - Processed graph dataset (~962 MB)
- `trained_gnn_model.pt` - Trained model weights
- `confusion_matrix.png` - Evaluation visualization
- Console output with training metrics and test set results

---

## **6. Understanding the Project Structure**

```
GNN_project/
├── configs/
│   └── base_config.yaml           # Central configuration file
├── data/
│   ├── advisory-database/         # GitHub security advisories (submodule)
│   └── python/                    # CodeSearchNet Python data
├── scripts/
│   ├── 01_create_dataset.py       # Dataset creation script
│   └── 02_train_model.py          # Model training script
├── src/
│   ├── data_processing/
│   │   └── graph_utils.py         # AST to graph conversion utilities
│   ├── modeling/
│   │   └── model.py               # GNN model architecture (GCN + GAT)
│   ├── training/                  # Training utilities
│   ├── create_labeled_dataset.py  # Advisory data processing
│   ├── filter_python_advisories.py # Python advisory filtering
│   ├── train_gnn.py               # Training logic
│   └── evaluate_model.py          # Model evaluation
├── run_pipeline.py                # Main orchestration script
├── requirements.txt               # Python dependencies
├── GUIDE.md                       # This file
└── README.md                      # Project overview
```

---

## **7. Common Issues & Troubleshooting**

### **Issue: Missing `data/` directory**

- **Solution:** Follow Steps 1-3 above to download and process the data from Kaggle and GitHub.

### **Issue: `FileNotFoundError` when running scripts**

- **Solution:** Ensure you're in the project root directory and all required `.pt`, `.json`, and `.pkl` files are present.

### **Issue: CUDA/GPU errors**

- **Solution:** The project uses PyTorch with GPU support. If you don't have a GPU, the code will automatically fall back to CPU (but training will be slower).

### **Issue: `ModuleNotFoundError: No module named 'yaml'`**

- **Solution:** Install PyYAML: `pip install pyyaml`

### **Issue: Out of Memory (OOM) errors during training**

- **Solutions:**
  - Reduce `batch_size` in `configs/base_config.yaml` (try 32 or 16)
  - Reduce `max_safe_examples` to process fewer code samples
  - Reduce `max_nodes_per_graph` to limit graph size
  - Use a machine with more RAM (16+ GB recommended)

### **Issue: Training is very slow**

- **Solutions:**
  - Ensure you're using GPU acceleration (check `device: "auto"` in config)
  - Reduce the dataset size by lowering `max_safe_examples`
  - Reduce model complexity: lower `gcn_layers`, `hidden_channels`, or `gat_heads`

### **Issue: AST parsing errors ("SyntaxError" in logs)**

- **Solution:** This is normal. Some code snippets in CodeSearchNet may have syntax errors. The `graph_utils.py` module catches these and skips malformed code automatically.

---

## **8. Model Architecture Details**

The `VulnerabilityGNN` model uses:

1. **Graph Convolutional Network (GCN) Layers**: Extract hierarchical features from code AST
2. **Graph Attention Network (GAT) Layer**: Focus on important nodes (e.g., security-critical operations)
3. **Global Pooling**: Aggregate node features into a graph-level representation
4. **MLP Classifier**: Binary classification (vulnerable/safe)

**Key Features:**
- Handles imbalanced datasets with weighted cross-entropy loss
- Early stopping with validation set monitoring
- Configurable architecture via `configs/base_config.yaml`

---

## **9. Dataset Information**

**Vulnerable Code Examples:**
- Source: GitHub Security Advisory Database
- Contains real-world Python vulnerabilities with CVE identifiers
- Examples include SQL injection, XSS, path traversal, etc.

**Safe Code Examples:**
- Source: CodeSearchNet Python dataset (200,000+ functions)
- High-quality, production code from open-source repositories
- Filtered and deduplicated

**Graph Representation:**
- Code is parsed into Abstract Syntax Trees (ASTs)
- Each AST node becomes a graph node with type features
- Parent-child relationships become directed edges
- Maximum 100 nodes per graph (configurable)

---

## **Additional Resources**

- **PyTorch Geometric Documentation:** [https://pytorch-geometric.readthedocs.io/](https://pytorch-geometric.readthedocs.io/)
- **CodeSearchNet Dataset:** [https://github.com/github/CodeSearchNet](https://github.com/github/CodeSearchNet)
- **GitHub Advisory Database:** [https://github.com/github/advisory-database](https://github.com/github/advisory-database)
- **Graph Neural Networks Tutorial:** [https://distill.pub/2021/gnn-intro/](https://distill.pub/2021/gnn-intro/)

---
