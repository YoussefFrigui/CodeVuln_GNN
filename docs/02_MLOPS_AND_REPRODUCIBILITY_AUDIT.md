### **FILE 3: `02_MLOPS_AND_REPRODUCIBILITY_AUDIT.md`**

#### **1. Configuration Management Failure Points**
The project is critically flawed by hardcoded configurations. This makes experiments impossible to reproduce reliably.

-   **File Paths:**
    -   **FIXED:** Now uses centralized `configs/base_config.yaml` for all paths
    -   All scripts read from config: `final_graph_dataset.pt`, `trained_gnn_model.pt`
    -   *Status:* Issue resolved through config-driven architecture

-   **Hyperparameters:**
    -   **FIXED:** All hyperparameters now in `configs/base_config.yaml`
    -   No more hardcoded values in training scripts
    -   *Status:* Issue resolved, all parameters configurable

#### **2. Dependency Management**
-   The `requirements.txt` file is a good start, but it is insufficient for true reproducibility.
-   **Critique:**
    -   **Unpinned Versions:** Versions are not pinned (e.g., `torch` instead of `torch==2.1.0`). A `pip install -r requirements.txt` executed today will yield different package versions than one executed in six months, potentially breaking the code or changing model behavior silently.
    -   **Solution:** Use a dependency management tool like Poetry or PDM to generate a lock file (`poetry.lock` or `pdm.lock`) that guarantees byte-for-byte identical environments. At a minimum, pin all versions in `requirements.txt` using `pip freeze > requirements.txt`.

#### **3. Data Pipeline & Versioning**
-   The data processing scripts (`01_create_dataset.py`, `create_labeled_dataset.py`, etc.) are not deterministic and lack any form of versioning.
-   **Critique:**
    -   **Determinism:** The scripts appear to be deterministic in logic, but they depend on external data (`advisory-database`) that can change. If the git submodule is updated, re-running the scripts will produce a different dataset.
    -   **Data Versioning:** There is no concept of data versioning. If you change a processing step, the old `final_graph_dataset.pt` is simply overwritten. It is impossible to revert to a previous version of the dataset or link a trained model to the exact data version it was trained on.
    -   **Solution:** Implement a data versioning tool like DVC. Each dataset and intermediate file should be versioned, allowing you to check out a specific version of your data just like you check out a specific version of your code.

#### **4. Experiment Tracking**
-   **FIXED:** MLflow experiment tracking now implemented
    -   All training runs logged to `outputs/mlruns/`
    -   Tracks 32 parameters, metrics per epoch, and model artifacts
    -   Model file: `trained_gnn_model.pt`
-   **Benefits:**
    -   Institutional memory preserved across experiments
    -   Easy comparison of different runs
    -   No more wasted effort re-running known experiments
    -   **Solution:** Integrate MLflow or Weights & Biases immediately. Log all hyperparameters, evaluation metrics, and model artifacts for every single training run.
