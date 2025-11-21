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

import torch
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from torch.optim import Adam
from torch_geometric.data import DataLoader, Data
from tqdm import tqdm

from src.modeling.model import VulnerabilityGNN


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
    ):
        self.model = model.to(device)
        self.device = device
        self.config = config
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

            if val_loss < best_val_loss:
                best_val_loss = val_loss
                patience_counter = 0
                best_model_state = self.model.state_dict()
                print(f"  -> New best model found (val_loss: {val_loss:.4f})")
            else:
                patience_counter += 1
                if patience_counter >= self.config["training"]["patience"]:
                    print(f"Early stopping at epoch {epoch+1}.")
                    break
        
        total_time = time.time() - total_start_time
        print(f"\nTraining finished in {total_time/60:.2f} minutes.")

        if best_model_state:
            self.model.load_state_dict(best_model_state)


def get_device(device_config: str) -> str:
    """Determines the compute device to use."""
    if device_config == "auto":
        return "cuda" if torch.cuda.is_available() else "cpu"
    return device_config


def train_model(config: Dict[str, Any]):
    """Main function to orchestrate the training process."""
    device = get_device(config["training"]["device"])
    print(f"Using device: {device}")

    # Load data
    print("Loading processed dataset...")
    dataset: List[Data] = torch.load(config["data"]["processed_dataset_path"])
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
    trainer = Trainer(model, device, config, class_weights)

    # Run training
    trainer.run_training(train_loader, val_loader)

    # Evaluate on test set
    print("\nEvaluating on the test set...")
    test_metrics = trainer.evaluate(test_loader)
    print(f"Test Set Results: {test_metrics}")

    # Save the final model
    model_save_path = config["output"]["model_save_path"]
    torch.save(model.state_dict(), model_save_path)
    print(f"Model saved to {model_save_path}")


if __name__ == "__main__":
    import yaml

    print("Running model training as a standalone script.")
    with open("configs/base_config.yaml", "r") as f:
        config = yaml.safe_load(f)
    train_model(config)
