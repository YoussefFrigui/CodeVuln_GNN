### **FILE 3: `02_MLOPS_AND_REPRODUCIBILITY_AUDIT.md`**

#### **1. Configuration Management Failure Points**
The project is critically flawed by hardcoded configurations. This makes experiments impossible to reproduce reliably.

-   **File Paths:**
    -   `run_pipeline.py`: Hardcodes paths to every script it runs (e.g., `'scripts/01_create_dataset.py'`).
    -   `scripts/01_create_dataset.py`: Hardcodes `"massive_codesearchnet_dataset.pt"`.
    -   `scripts/02_train_model.py`: Hardcodes `"massive_codesearchnet_dataset.pt"` and `"vulnerability_gnn_model.pt"`.
    -   `src/filter_python_advisories.py`: Hardcodes `"data/advisory-database/advisories/github-reviewed/"` and `"python_advisories.json"`.
    -   *Critique:* This is the most severe issue. A centralized configuration file (e.g., `configs/base_config.yaml`) must be implemented to manage all paths.

-   **Hyperparameters:**
    -   `scripts/02_train_model.py`: Hardcodes `hidden_channels=64`, `epochs=100`, and `lr=0.01`.
    -   `src/train_gnn.py`: Also contains hardcoded `epochs=100`, `lr=0.01`.
    -   *Critique:* These values define the model and training process. Hardcoding them prevents systematic hyperparameter tuning and makes it impossible to know what parameters were used for a given model artifact.

#### **2. Dependency Management**
-   The `requirements.txt` file is a good start, but it is insufficient for true reproducibility.
-   **Critique:**
    -   **Unpinned Versions:** Versions are not pinned (e.g., `torch` instead of `torch==2.1.0`). A `pip install -r requirements.txt` executed today will yield different package versions than one executed in six months, potentially breaking the code or changing model behavior silently.
    -   **Solution:** Use a dependency management tool like Poetry or PDM to generate a lock file (`poetry.lock` or `pdm.lock`) that guarantees byte-for-byte identical environments. At a minimum, pin all versions in `requirements.txt` using `pip freeze > requirements.txt`.

#### **3. Data Pipeline & Versioning**
-   The data processing scripts (`01_create_dataset.py`, `create_labeled_dataset.py`, etc.) are not deterministic and lack any form of versioning.
-   **Critique:**
    -   **Determinism:** The scripts appear to be deterministic in logic, but they depend on external data (`advisory-database`) that can change. If the git submodule is updated, re-running the scripts will produce a different dataset.
    -   **Data Versioning:** There is no concept of data versioning. If you change a processing step, the old `massive_codesearchnet_dataset.pt` is simply overwritten. It is impossible to revert to a previous version of the dataset or link a trained model to the exact data version it was trained on.
    -   **Solution:** Implement a data versioning tool like DVC. Each dataset and intermediate file should be versioned, allowing you to check out a specific version of your data just like you check out a specific version of your code.

#### **4. Experiment Tracking**
-   There is a complete absence of experiment tracking. The current workflow appears to be: run a script, see console output, and have a single model file (`vulnerability_gnn_model.pt`) overwritten with each run.
-   **Direct Negative Impact:**
    -   **No Institutional Memory:** It is impossible to know which hyperparameters, code version, and data version produced the current `.pt` file. All previous experiments are lost.
    -   **Inability to Compare Models:** You cannot systematically compare the results of different model architectures or hyperparameters, which is the core loop of ML research.
    -   **Wasted Effort:** You will inevitably waste time re-running experiments because you can't remember or prove what you have already tried.
    -   **Solution:** Integrate MLflow or Weights & Biases immediately. Log all hyperparameters, evaluation metrics, and model artifacts for every single training run.
