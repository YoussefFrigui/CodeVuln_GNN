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
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, confusion_matrix, classification_report, roc_curve, auc, precision_recall_curve
from sklearn.model_selection import train_test_split
from torch.optim import Adam
import torch.nn as nn
from torch_geometric.data import DataLoader, Data
from tqdm import tqdm
import numpy as np

try:
    import mlflow
    import mlflow.pytorch
    MLFLOW_AVAILABLE = True
except ImportError:
    MLFLOW_AVAILABLE = False
    print("Warning: MLflow not available. Install with: pip install mlflow")

try:
    import matplotlib
    matplotlib.use('Agg')  # Non-interactive backend
    import matplotlib.pyplot as plt
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False
    print("Warning: Matplotlib not available for charts")

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent))
from modeling.model import VulnerabilityGNN


def create_and_log_charts(y_true, y_pred, y_probs, output_dir: str = "outputs/charts"):
    """Create evaluation charts and save them for MLflow logging."""
    if not MATPLOTLIB_AVAILABLE:
        print("Matplotlib not available, skipping chart generation")
        return []
    
    os.makedirs(output_dir, exist_ok=True)
    chart_paths = []
    
    # 1. Confusion Matrix
    plt.figure(figsize=(8, 6))
    cm = confusion_matrix(y_true, y_pred)
    plt.imshow(cm, interpolation='nearest', cmap=plt.cm.Blues)
    plt.title('Confusion Matrix', fontsize=14)
    plt.colorbar()
    classes = ['Safe', 'Vulnerable']
    tick_marks = [0, 1]
    plt.xticks(tick_marks, classes)
    plt.yticks(tick_marks, classes)
    
    # Add text annotations
    thresh = cm.max() / 2.
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            plt.text(j, i, format(cm[i, j], 'd'),
                    ha="center", va="center",
                    color="white" if cm[i, j] > thresh else "black",
                    fontsize=12)
    
    plt.ylabel('True Label', fontsize=12)
    plt.xlabel('Predicted Label', fontsize=12)
    plt.tight_layout()
    cm_path = os.path.join(output_dir, 'confusion_matrix.png')
    plt.savefig(cm_path, dpi=150)
    plt.close()
    chart_paths.append(cm_path)
    
    # 2. ROC Curve
    plt.figure(figsize=(8, 6))
    fpr, tpr, _ = roc_curve(y_true, y_probs)
    roc_auc = auc(fpr, tpr)
    plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (AUC = {roc_auc:.3f})')
    plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--', label='Random')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate', fontsize=12)
    plt.ylabel('True Positive Rate', fontsize=12)
    plt.title('ROC Curve', fontsize=14)
    plt.legend(loc="lower right")
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    roc_path = os.path.join(output_dir, 'roc_curve.png')
    plt.savefig(roc_path, dpi=150)
    plt.close()
    chart_paths.append(roc_path)
    
    # 3. Precision-Recall Curve
    plt.figure(figsize=(8, 6))
    precision, recall, _ = precision_recall_curve(y_true, y_probs)
    pr_auc = auc(recall, precision)
    plt.plot(recall, precision, color='green', lw=2, label=f'PR curve (AUC = {pr_auc:.3f})')
    plt.xlabel('Recall', fontsize=12)
    plt.ylabel('Precision', fontsize=12)
    plt.title('Precision-Recall Curve', fontsize=14)
    plt.legend(loc="lower left")
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    pr_path = os.path.join(output_dir, 'precision_recall_curve.png')
    plt.savefig(pr_path, dpi=150)
    plt.close()
    chart_paths.append(pr_path)
    
    # 4. Score Distribution
    plt.figure(figsize=(10, 6))
    y_true_arr = np.array(y_true)
    y_probs_arr = np.array(y_probs)
    
    plt.hist(y_probs_arr[y_true_arr == 0], bins=50, alpha=0.7, label='Safe Code', color='green')
    plt.hist(y_probs_arr[y_true_arr == 1], bins=50, alpha=0.7, label='Vulnerable Code', color='red')
    plt.xlabel('Vulnerability Score', fontsize=12)
    plt.ylabel('Count', fontsize=12)
    plt.title('Score Distribution by Class', fontsize=14)
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    dist_path = os.path.join(output_dir, 'score_distribution.png')
    plt.savefig(dist_path, dpi=150)
    plt.close()
    chart_paths.append(dist_path)
    
    # 5. Per-class metrics bar chart
    plt.figure(figsize=(10, 6))
    report = classification_report(y_true, y_pred, target_names=['Safe', 'Vulnerable'], output_dict=True)
    
    metrics = ['precision', 'recall', 'f1-score']
    safe_scores = [report['Safe'][m] for m in metrics]
    vuln_scores = [report['Vulnerable'][m] for m in metrics]
    
    x = np.arange(len(metrics))
    width = 0.35
    
    bars1 = plt.bar(x - width/2, safe_scores, width, label='Safe', color='green', alpha=0.7)
    bars2 = plt.bar(x + width/2, vuln_scores, width, label='Vulnerable', color='red', alpha=0.7)
    
    plt.ylabel('Score', fontsize=12)
    plt.title('Per-Class Metrics', fontsize=14)
    plt.xticks(x, ['Precision', 'Recall', 'F1-Score'])
    plt.ylim(0, 1.1)
    plt.legend()
    plt.grid(True, alpha=0.3, axis='y')
    
    # Add value labels
    for bar in bars1 + bars2:
        height = bar.get_height()
        plt.annotate(f'{height:.2f}',
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3), textcoords="offset points",
                    ha='center', va='bottom', fontsize=10)
    
    plt.tight_layout()
    metrics_path = os.path.join(output_dir, 'per_class_metrics.png')
    plt.savefig(metrics_path, dpi=150)
    plt.close()
    chart_paths.append(metrics_path)
    
    print(f"📊 Generated {len(chart_paths)} charts in {output_dir}")
    return chart_paths


def create_training_history_charts(history: Dict[str, List[float]], output_dir: str = "outputs/charts"):
    """Create training history charts."""
    if not MATPLOTLIB_AVAILABLE:
        return []
    
    os.makedirs(output_dir, exist_ok=True)
    chart_paths = []
    epochs = range(1, len(history["train_loss"]) + 1)
    
    # 1. Loss curves
    plt.figure(figsize=(10, 6))
    plt.plot(epochs, history["train_loss"], 'b-', label='Training Loss', linewidth=2)
    plt.plot(epochs, history["val_loss"], 'r-', label='Validation Loss', linewidth=2)
    plt.xlabel('Epoch', fontsize=12)
    plt.ylabel('Loss', fontsize=12)
    plt.title('Training and Validation Loss', fontsize=14)
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    loss_path = os.path.join(output_dir, 'loss_curves.png')
    plt.savefig(loss_path, dpi=150)
    plt.close()
    chart_paths.append(loss_path)
    
    # 2. Accuracy curves
    plt.figure(figsize=(10, 6))
    plt.plot(epochs, history["train_acc"], 'b-', label='Training Accuracy', linewidth=2)
    plt.plot(epochs, history["val_acc"], 'r-', label='Validation Accuracy', linewidth=2)
    plt.xlabel('Epoch', fontsize=12)
    plt.ylabel('Accuracy', fontsize=12)
    plt.title('Training and Validation Accuracy', fontsize=14)
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.ylim(0, 1.05)
    plt.tight_layout()
    acc_path = os.path.join(output_dir, 'accuracy_curves.png')
    plt.savefig(acc_path, dpi=150)
    plt.close()
    chart_paths.append(acc_path)
    
    # 3. F1 Score over epochs
    plt.figure(figsize=(10, 6))
    plt.plot(epochs, history["val_f1"], 'g-', label='Validation F1', linewidth=2, marker='o', markersize=4)
    plt.xlabel('Epoch', fontsize=12)
    plt.ylabel('F1 Score', fontsize=12)
    plt.title('Validation F1 Score Over Training', fontsize=14)
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.ylim(0, 1.05)
    plt.tight_layout()
    f1_path = os.path.join(output_dir, 'f1_curve.png')
    plt.savefig(f1_path, dpi=150)
    plt.close()
    chart_paths.append(f1_path)
    
    print(f"📊 Generated {len(chart_paths)} training history charts")
    return chart_paths


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
        y_true, y_pred, y_probs = [], [], []
        total_loss = 0.0

        with torch.no_grad():
            progress_bar = tqdm(loader, desc="Evaluating", leave=False)
            for data in progress_bar:
                data = data.to(self.device)
                out = self.model(data.x, data.edge_index, data.batch)
                loss = self.criterion(out, data.y.squeeze())
                total_loss += loss.item()
                
                probs = torch.softmax(out, dim=1)
                pred = out.argmax(dim=1)
                
                y_true.extend(data.y.squeeze().cpu().numpy())
                y_pred.extend(pred.cpu().numpy())
                y_probs.extend(probs[:, 1].cpu().numpy())  # Probability of vulnerable class

        return {
            "loss": total_loss / len(loader),
            "accuracy": accuracy_score(y_true, y_pred),
            "precision": precision_score(y_true, y_pred, average="weighted", zero_division=0),
            "recall": recall_score(y_true, y_pred, average="weighted", zero_division=0),
            "f1": f1_score(y_true, y_pred, average="weighted", zero_division=0),
            "y_true": y_true,
            "y_pred": y_pred,
            "y_probs": y_probs,
        }

    def run_training(self, train_loader: DataLoader, val_loader: DataLoader):
        """Main training loop with early stopping."""
        best_val_loss = float("inf")
        patience_counter = 0
        best_model_state = None
        
        # Track history for charts
        self.history = {
            "train_loss": [],
            "train_acc": [],
            "val_loss": [],
            "val_acc": [],
            "val_f1": [],
        }

        total_start_time = time.time()
        for epoch in range(self.config["training"]["num_epochs"]):
            epoch_start_time = time.time()

            train_loss, train_acc = self.train_epoch(train_loader)
            val_metrics = self.evaluate(val_loader)
            val_loss = val_metrics["loss"]
            
            # Store history
            self.history["train_loss"].append(train_loss)
            self.history["train_acc"].append(train_acc)
            self.history["val_loss"].append(val_loss)
            self.history["val_acc"].append(val_metrics["accuracy"])
            self.history["val_f1"].append(val_metrics["f1"])

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
                # Deep copy to prevent overwriting when model continues training
                best_model_state = {k: v.clone() for k, v in self.model.state_dict().items()}
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
            use_batch_norm=config["model"].get("use_batch_norm", True),
            use_residual=config["model"].get("use_residual", True),
        )
        trainer = Trainer(model, device, config, class_weights, mlflow_enabled=mlflow_enabled)

        # Run training
        trainer.run_training(train_loader, val_loader)
        
        # Log training history charts
        if mlflow_enabled and config["mlflow"].get("log_artifacts", True) and hasattr(trainer, 'history'):
            print("\n📊 Generating training history charts...")
            history_charts = create_training_history_charts(trainer.history)
            for chart_path in history_charts:
                mlflow.log_artifact(chart_path, artifact_path="charts")
            print(f"✅ Logged {len(history_charts)} training history charts to MLflow")

        # Evaluate on test set
        print("\nEvaluating on the test set...")
        test_metrics = trainer.evaluate(test_loader)
        
        # Extract predictions for charts
        y_true = test_metrics.pop("y_true")
        y_pred = test_metrics.pop("y_pred")
        y_probs = test_metrics.pop("y_probs")
        
        print(f"Test Set Results: {test_metrics}")
        
        # Print detailed classification report
        print("\n" + "="*50)
        print("Classification Report:")
        print("="*50)
        print(classification_report(y_true, y_pred, target_names=['Safe', 'Vulnerable']))
        
        # Log test metrics to MLflow
        if mlflow_enabled:
            mlflow.log_metrics({
                "test_loss": test_metrics["loss"],
                "test_accuracy": test_metrics["accuracy"],
                "test_precision": test_metrics["precision"],
                "test_recall": test_metrics["recall"],
                "test_f1": test_metrics["f1"],
            })
            
            # Calculate and log additional metrics
            cm = confusion_matrix(y_true, y_pred)
            tn, fp, fn, tp = cm.ravel()
            
            # Per-class metrics
            vuln_precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            vuln_recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            vuln_f1 = 2 * vuln_precision * vuln_recall / (vuln_precision + vuln_recall) if (vuln_precision + vuln_recall) > 0 else 0
            
            safe_precision = tn / (tn + fn) if (tn + fn) > 0 else 0
            safe_recall = tn / (tn + fp) if (tn + fp) > 0 else 0
            
            # ROC AUC
            fpr, tpr, _ = roc_curve(y_true, y_probs)
            roc_auc_score = auc(fpr, tpr)
            
            # PR AUC
            precision_curve, recall_curve, _ = precision_recall_curve(y_true, y_probs)
            pr_auc_score = auc(recall_curve, precision_curve)
            
            mlflow.log_metrics({
                "test_roc_auc": roc_auc_score,
                "test_pr_auc": pr_auc_score,
                "test_true_positives": int(tp),
                "test_true_negatives": int(tn),
                "test_false_positives": int(fp),
                "test_false_negatives": int(fn),
                "test_vulnerable_precision": vuln_precision,
                "test_vulnerable_recall": vuln_recall,
                "test_vulnerable_f1": vuln_f1,
                "test_safe_precision": safe_precision,
                "test_safe_recall": safe_recall,
            })
            
            print(f"\n📈 ROC AUC: {roc_auc_score:.4f}")
            print(f"📈 PR AUC: {pr_auc_score:.4f}")
        
        # Generate and log charts
        if mlflow_enabled and config["mlflow"].get("log_artifacts", True):
            print("\n📊 Generating evaluation charts...")
            chart_paths = create_and_log_charts(y_true, y_pred, y_probs)
            
            # Log charts to MLflow
            for chart_path in chart_paths:
                mlflow.log_artifact(chart_path, artifact_path="charts")
            print(f"✅ Logged {len(chart_paths)} charts to MLflow")

        # Save the final model
        model_save_path = config["output"]["model_save_path"]
        torch.save(model.state_dict(), model_save_path)
        print(f"Model saved to {model_save_path}")
        
        # Save data splits for evaluation
        splits_path = "outputs/datasets/data_splits.pt"
        torch.save({
            'train_data': train_dataset,
            'val_data': val_dataset,
            'test_data': test_dataset,
            'train_labels': [d.y.item() for d in train_dataset],
            'val_labels': [d.y.item() for d in val_dataset],
            'test_labels': [d.y.item() for d in test_dataset],
        }, splits_path)
        print(f"Data splits saved to {splits_path}")
        
        # Print split statistics
        test_safe = sum(1 for d in test_dataset if d.y.item() == 0)
        test_vuln = sum(1 for d in test_dataset if d.y.item() == 1)
        print(f"Test set composition: {test_safe} safe, {test_vuln} vulnerable")
        
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
