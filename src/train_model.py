"""
Model Training and Evaluation Script

This script orchestrates the training and evaluation of the GNN model for
vulnerability detection. It is designed to be driven by a configuration file
and handles the following responsibilities:
- Loading the processed dataset.
- Splitting the data into training, validation, and test sets.
- Calculating class weights to handle dataset imbalance.
- Initializing the GNN model, optimizer, and loss function.
- Running the training loop with progress tracking and early stopping.
- Evaluating the best model on the test set.
- Saving the trained model.
"""

import time
from typing import Any, Dict, List, Tuple
import os
import sys
from pathlib import Path
from datetime import datetime

import torch
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from torch.optim import Adam
import torch.nn as nn
from torch_geometric.data import DataLoader, Data
from tqdm import tqdm

try:
    import mlflow
    import mlflow.pytorch
    MLFLOW_AVAILABLE = True
except ImportError:
    MLFLOW_AVAILABLE = False
    print("Warning: MLflow not available. Install with: pip install mlflow")

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent))
from modeling.model import VulnerabilityGNN


class Trainer:
    """
    Handles the training and evaluation of the VulnerabilityGNN model.
    """

    def __init__(
        self,
        model: VulnerabilityGNN,
        device: str,
        config: Dict[str, Any],
        class_weights: List[float] = None,
        mlflow_enabled: bool = False,
    ):
        self.model = model.to(device)
        self.device = device
        self.config = config
        self.mlflow_enabled = mlflow_enabled and MLFLOW_AVAILABLE
        self.optimizer = Adam(
            model.parameters(),
            lr=config["training"]["learning_rate"],
            weight_decay=config["training"]["weight_decay"],
        )

        # Use weighted loss if class weights are provided
        if class_weights:
            self.criterion = nn.CrossEntropyLoss(
                weight=torch.tensor(class_weights, dtype=torch.float).to(device)
            )
            print(f"Using weighted loss with weights: {class_weights}")
        else:
            self.criterion = nn.CrossEntropyLoss()

    def train_epoch(self, train_loader: DataLoader) -> Tuple[float, float]:
        """Runs a single training epoch."""
        self.model.train()
        total_loss = 0.0
        correct = 0
        total = 0

        progress_bar = tqdm(train_loader, desc="Training", leave=False)
        for data in progress_bar:
            data = data.to(self.device)
            self.optimizer.zero_grad()

            out = self.model(data.x, data.edge_index, data.batch)
            loss = self.criterion(out, data.y.squeeze())
            loss.backward()
            self.optimizer.step()

            total_loss += loss.item()
            pred = out.argmax(dim=1)
            correct += (pred == data.y.squeeze()).sum().item()
            total += data.y.size(0)

            progress_bar.set_postfix(
                {"loss": f"{loss.item():.4f}", "acc": f"{correct / total:.4f}"}
            )
        return total_loss / len(train_loader), correct / total

    def evaluate(self, loader: DataLoader) -> Dict[str, float]:
        """Evaluates the model on a given data loader."""
        self.model.eval()
        y_true, y_pred = [], []
        total_loss = 0.0

        with torch.no_grad():
            progress_bar = tqdm(loader, desc="Evaluating", leave=False)
            for data in progress_bar:
                data = data.to(self.device)
                out = self.model(data.x, data.edge_index, data.batch)
                loss = self.criterion(out, data.y.squeeze())
                total_loss += loss.item()
                pred = out.argmax(dim=1)
                y_true.extend(data.y.squeeze().cpu().numpy())
                y_pred.extend(pred.cpu().numpy())

        return {
            "loss": total_loss / len(loader),
            "accuracy": accuracy_score(y_true, y_pred),
            "precision": precision_score(y_true, y_pred, average="weighted", zero_division=0),
            "recall": recall_score(y_true, y_pred, average="weighted", zero_division=0),
            "f1": f1_score(y_true, y_pred, average="weighted", zero_division=0),
        }

    def run_training(self, train_loader: DataLoader, val_loader: DataLoader):
        """Main training loop with early stopping."""
        best_val_loss = float("inf")
        patience_counter = 0
        best_model_state = None

        total_start_time = time.time()
        for epoch in range(self.config["training"]["num_epochs"]):
            epoch_start_time = time.time()

            train_loss, train_acc = self.train_epoch(train_loader)
            val_metrics = self.evaluate(val_loader)
            val_loss = val_metrics["loss"]

            epoch_time = time.time() - epoch_start_time
            print(
                f"Epoch {epoch+1:03d} [{epoch_time:.1f}s]: "
                f"Train Loss: {train_loss:.4f}, Train Acc: {train_acc:.4f} | "
                f"Val Loss: {val_loss:.4f}, Val F1: {val_metrics['f1']:.4f}"
            )

            # Log metrics to MLflow
            if self.mlflow_enabled:
                mlflow.log_metrics({
                    "train_loss": train_loss,
                    "train_accuracy": train_acc,
                    "val_loss": val_loss,
                    "val_accuracy": val_metrics["accuracy"],
                    "val_precision": val_metrics["precision"],
                    "val_recall": val_metrics["recall"],
                    "val_f1": val_metrics["f1"],
                    "epoch_time_seconds": epoch_time,
                }, step=epoch)

            if val_loss < best_val_loss:
                best_val_loss = val_loss
                patience_counter = 0
                best_model_state = self.model.state_dict()
                print(f"  -> New best model found (val_loss: {val_loss:.4f})")
                
                # Log best metrics to MLflow
                if self.mlflow_enabled:
                    mlflow.log_metrics({
                        "best_val_loss": best_val_loss,
                        "best_epoch": epoch + 1,
                    })
            else:
                patience_counter += 1
                if patience_counter >= self.config["training"]["patience"]:
                    print(f"Early stopping at epoch {epoch+1}.")
                    if self.mlflow_enabled:
                        mlflow.log_metric("early_stopped_epoch", epoch + 1)
                    break
        
        total_time = time.time() - total_start_time
        print(f"\nTraining finished in {total_time/60:.2f} minutes.")
        
        # Log total training time
        if self.mlflow_enabled:
            mlflow.log_metric("total_training_time_minutes", total_time / 60)

        if best_model_state:
            self.model.load_state_dict(best_model_state)


def get_device(device_config: str) -> str:
    """Determines the compute device to use."""
    if device_config == "auto":
        return "cuda" if torch.cuda.is_available() else "cpu"
    return device_config


def train_model(config: Dict[str, Any]):
    """Main function to orchestrate the training process."""
    # Setup MLflow
    mlflow_enabled = config.get("mlflow", {}).get("enabled", False) and MLFLOW_AVAILABLE
    
    if mlflow_enabled:
        mlflow_config = config["mlflow"]
        mlflow.set_tracking_uri(mlflow_config["tracking_uri"])
        mlflow.set_experiment(mlflow_config["experiment_name"])
        
        # Start MLflow run
        run_name = f"{mlflow_config['run_name_prefix']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        mlflow.start_run(run_name=run_name)
        print(f"\n🔬 MLflow tracking enabled: {mlflow_config['tracking_uri']}")
        print(f"📊 Experiment: {mlflow_config['experiment_name']}")
        print(f"🏃 Run: {run_name}\n")
    
    try:
        device = get_device(config["training"]["device"])
        print(f"Using device: {device}")

        # Load data
        print("Loading processed dataset...")
        dataset: List[Data] = torch.load(config["data"]["processed_dataset_path"], weights_only=False)
        print(f"Loaded {len(dataset)} graphs.")

        # Stratified split
        labels = [data.y.item() for data in dataset]
        train_val_indices, test_indices = train_test_split(
            range(len(dataset)),
            test_size=config["training"]["test_split_size"],
            stratify=labels,
            random_state=config["training"]["random_state"],
        )
        
        train_val_dataset = [dataset[i] for i in train_val_indices]
        train_val_labels = [labels[i] for i in train_val_indices]
        test_dataset = [dataset[i] for i in test_indices]

        train_indices, val_indices = train_test_split(
            range(len(train_val_dataset)),
            test_size=config["training"]["validation_split_size"],
            stratify=train_val_labels,
            random_state=config["training"]["random_state"],
        )

        train_dataset = [train_val_dataset[i] for i in train_indices]
        val_dataset = [train_val_dataset[i] for i in val_indices]

        print(f"Dataset split: Train={len(train_dataset)}, Val={len(val_dataset)}, Test={len(test_dataset)}")

        # Calculate class weights
        num_safe = sum(1 for data in train_dataset if data.y.item() == 0)
        num_vuln = len(train_dataset) - num_safe
        total = len(train_dataset)
        class_weights = [total / (2 * num_safe), total / (2 * num_vuln)]
        
        # Log parameters and dataset info to MLflow
        if mlflow_enabled:
            # Log all hyperparameters
            mlflow.log_params({
                # Model architecture
                "num_node_features": config["model"]["num_node_features"],
                "hidden_channels": config["model"]["hidden_channels"],
                "num_classes": config["model"]["num_classes"],
                "dropout": config["model"]["dropout"],
                "gcn_layers": config["model"]["gcn_layers"],
                "gat_heads": config["model"]["gat_heads"],
                # Training parameters
                "learning_rate": config["training"]["learning_rate"],
                "weight_decay": config["training"]["weight_decay"],
                "batch_size": config["training"]["batch_size"],
                "num_epochs": config["training"]["num_epochs"],
                "patience": config["training"]["patience"],
                "device": device,
                # Dataset parameters
                "max_safe_examples": config["dataset"]["max_safe_examples"],
                "max_nodes_per_graph": config["dataset"]["max_nodes_per_graph"],
                "test_split_size": config["training"]["test_split_size"],
                "validation_split_size": config["training"]["validation_split_size"],
                "random_state": config["training"]["random_state"],
            })
            
            # Log dataset statistics
            mlflow.log_metrics({
                "total_samples": len(dataset),
                "train_samples": len(train_dataset),
                "val_samples": len(val_dataset),
                "test_samples": len(test_dataset),
                "train_safe_samples": num_safe,
                "train_vulnerable_samples": num_vuln,
                "class_imbalance_ratio": num_safe / num_vuln if num_vuln > 0 else 0,
                "class_weight_safe": class_weights[0],
                "class_weight_vulnerable": class_weights[1],
            })
            
            # Log tags for easier filtering
            mlflow.set_tags({
                "model_type": "GNN",
                "architecture": "GCN+GAT",
                "task": "vulnerability_detection",
                "dataset": "github_advisories_codesearchnet",
            })

        # Create DataLoaders
        train_loader = DataLoader(train_dataset, batch_size=config["training"]["batch_size"], shuffle=True)
        val_loader = DataLoader(val_dataset, batch_size=config["training"]["batch_size"])
        test_loader = DataLoader(test_dataset, batch_size=config["training"]["batch_size"])

        # Initialize model and trainer
        model = VulnerabilityGNN(
            num_node_features=config["model"]["num_node_features"],
            hidden_channels=config["model"]["hidden_channels"],
            num_classes=config["model"]["num_classes"],
            dropout=config["model"]["dropout"],
            gcn_layers=config["model"]["gcn_layers"],
            gat_heads=config["model"]["gat_heads"],
        )
        trainer = Trainer(model, device, config, class_weights, mlflow_enabled=mlflow_enabled)

        # Run training
        trainer.run_training(train_loader, val_loader)

        # Evaluate on test set
        print("\nEvaluating on the test set...")
        test_metrics = trainer.evaluate(test_loader)
        print(f"Test Set Results: {test_metrics}")
        
        # Log test metrics to MLflow
        if mlflow_enabled:
            mlflow.log_metrics({
                "test_loss": test_metrics["loss"],
                "test_accuracy": test_metrics["accuracy"],
                "test_precision": test_metrics["precision"],
                "test_recall": test_metrics["recall"],
                "test_f1": test_metrics["f1"],
            })

        # Save the final model
        model_save_path = config["output"]["model_save_path"]
        torch.save(model.state_dict(), model_save_path)
        print(f"Model saved to {model_save_path}")
        
        # Log model to MLflow
        if mlflow_enabled and config["mlflow"].get("log_models", True):
            print("Logging model to MLflow...")
            # Log PyTorch model
            mlflow.pytorch.log_model(
                pytorch_model=model,
                artifact_path="model",
                registered_model_name="VulnerabilityGNN",
            )
            # Also log the state dict as artifact
            mlflow.log_artifact(model_save_path, artifact_path="model_weights")
        
        # Log config file as artifact
        if mlflow_enabled and config["mlflow"].get("log_artifacts", True):
            mlflow.log_artifact("configs/base_config.yaml", artifact_path="config")
            
    finally:
        # End MLflow run
        if mlflow_enabled:
            mlflow.end_run()
            print("\n✅ MLflow run completed")


if __name__ == "__main__":
    import yaml

    print("Running model training as a standalone script.")
    with open("configs/base_config.yaml", "r") as f:
        config = yaml.safe_load(f)
    train_model(config)
