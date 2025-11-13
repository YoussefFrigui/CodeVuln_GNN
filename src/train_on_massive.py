#!/usr/bin/env python3
"""
Train GNN on Massive CodeSearchNet Dataset
Uses the full dataset created by create_massive_dataset.py
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GCNConv, GATConv, global_mean_pool, global_max_pool
from torch_geometric.data import DataLoader
from torch.optim import Adam
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.model_selection import train_test_split
import numpy as np
import time
from tqdm import tqdm


class VulnerabilityGNN(nn.Module):
    """Graph Neural Network for Code Vulnerability Detection."""

    def __init__(self, num_node_features, hidden_channels=128, num_classes=2, dropout=0.3):
        super(VulnerabilityGNN, self).__init__()

        # GCN layers (deeper network for massive dataset)
        self.conv1 = GCNConv(num_node_features, hidden_channels)
        self.conv2 = GCNConv(hidden_channels, hidden_channels)
        self.conv3 = GCNConv(hidden_channels, hidden_channels)
        self.conv4 = GCNConv(hidden_channels, hidden_channels)

        # GAT layer for attention
        self.gat = GATConv(hidden_channels, hidden_channels, heads=8, concat=False)

        # Classification head
        self.lin1 = nn.Linear(hidden_channels, hidden_channels // 2)
        self.lin2 = nn.Linear(hidden_channels // 2, num_classes)

        self.dropout = dropout

    def forward(self, x, edge_index, batch):
        # GCN layers
        x = self.conv1(x, edge_index)
        x = F.relu(x)
        x = F.dropout(x, p=self.dropout, training=self.training)

        x = self.conv2(x, edge_index)
        x = F.relu(x)
        x = F.dropout(x, p=self.dropout, training=self.training)

        x = self.conv3(x, edge_index)
        x = F.relu(x)
        x = F.dropout(x, p=self.dropout, training=self.training)

        x = self.conv4(x, edge_index)
        x = F.relu(x)

        # GAT layer
        x = self.gat(x, edge_index)
        x = F.relu(x)

        # Global pooling
        x = global_mean_pool(x, batch) + global_max_pool(x, batch)

        # Classification
        x = self.lin1(x)
        x = F.relu(x)
        x = F.dropout(x, p=self.dropout, training=self.training)

        x = self.lin2(x)
        return x

class MassiveDatasetTrainer:
    """Trainer class for the massive CodeSearchNet dataset."""

    def __init__(self, model, device, class_weights=None):
        self.model = model.to(device)
        self.device = device
        self.optimizer = Adam(model.parameters(), lr=0.001, weight_decay=5e-4)

        # Handle class imbalance with weighted loss
        if class_weights is not None:
            self.criterion = nn.CrossEntropyLoss(weight=torch.tensor(class_weights, dtype=torch.float).to(device))
            print(f"Using weighted loss with weights: {class_weights}")
        else:
            self.criterion = nn.CrossEntropyLoss()

    def train_epoch(self, train_loader):
        self.model.train()
        total_loss = 0
        correct = 0
        total = 0

        # Progress bar for training batches
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

            # Update progress bar with current batch loss
            progress_bar.set_postfix({
                'loss': f'{loss.item():.4f}',
                'acc': f'{correct/total:.4f}'
            })

        progress_bar.close()
        return total_loss / len(train_loader), correct / total

    def validate(self, val_loader):
        self.model.eval()
        total_loss = 0
        y_true = []
        y_pred = []

        # Progress bar for validation batches
        progress_bar = tqdm(val_loader, desc="Validating", leave=False)

        with torch.no_grad():
            for data in progress_bar:
                data = data.to(self.device)
                out = self.model(data.x, data.edge_index, data.batch)
                loss = self.criterion(out, data.y.squeeze())

                total_loss += loss.item()
                pred = out.argmax(dim=1)

                y_true.extend(data.y.squeeze().cpu().numpy())
                y_pred.extend(pred.cpu().numpy())

                # Update progress bar with current batch loss
                progress_bar.set_postfix({
                    'loss': f'{loss.item():.4f}'
                })

        progress_bar.close()

        accuracy = accuracy_score(y_true, y_pred)
        precision = precision_score(y_true, y_pred, average='weighted', zero_division=0)
        recall = recall_score(y_true, y_pred, average='weighted', zero_division=0)
        f1 = f1_score(y_true, y_pred, average='weighted', zero_division=0)

        # Calculate per-class metrics for imbalanced dataset
        precision_per_class = precision_score(y_true, y_pred, average=None, zero_division=0)
        recall_per_class = recall_score(y_true, y_pred, average=None, zero_division=0)
        f1_per_class = f1_score(y_true, y_pred, average=None, zero_division=0)

        return total_loss / len(val_loader), accuracy, precision, recall, f1, precision_per_class, recall_per_class, f1_per_class

    def train(self, train_loader, val_loader, num_epochs=5, patience=5):
        best_val_loss = float('inf')
        patience_counter = 0
        best_model_state = None

        print(f"Starting training for {num_epochs} epochs...")
        total_start_time = time.time()

        # Progress bar for epochs
        epoch_progress = tqdm(range(num_epochs), desc="Epochs", unit="epoch")

        for epoch in epoch_progress:
            epoch_start_time = time.time()

            # Train epoch
            train_loss, train_acc = self.train_epoch(train_loader)
            train_time = time.time() - epoch_start_time

            # Validate
            val_start_time = time.time()
            val_results = self.validate(val_loader)
            val_loss, val_acc, val_prec, val_rec, val_f1, val_prec_per_class, val_rec_per_class, val_f1_per_class = val_results
            val_time = time.time() - val_start_time

            epoch_total_time = time.time() - epoch_start_time

            # Update epoch progress bar with current metrics
            epoch_progress.set_postfix({
                'train_loss': f'{train_loss:.4f}',
                'val_loss': f'{val_loss:.4f}',
                'val_acc': f'{val_acc:.4f}',
                'time': f'{epoch_total_time:.1f}s'
            })

            print(f"Epoch {epoch+1:03d} [{epoch_total_time:.1f}s]: "
                  f"Train Loss: {train_loss:.4f}, Train Acc: {train_acc:.4f} ({train_time:.1f}s) | "
                  f"Val Loss: {val_loss:.4f}, Val Acc: {val_acc:.4f}, "
                  f"Val F1: {val_f1:.4f} ({val_time:.1f}s)")
            print(f"  Per-class Val F1: Safe={val_f1_per_class[0]:.4f}, Vulnerable={val_f1_per_class[1]:.4f}")

            # Early stopping
            if val_loss < best_val_loss:
                best_val_loss = val_loss
                patience_counter = 0
                best_model_state = self.model.state_dict()
                print(f"  → New best model (val_loss: {val_loss:.4f})")
            else:
                patience_counter += 1
                if patience_counter >= patience:
                    print(f"Early stopping at epoch {epoch+1}")
                    epoch_progress.close()
                    break

        epoch_progress.close()
        total_training_time = time.time() - total_start_time
        print(f"\nTraining completed in {total_training_time:.1f} seconds ({total_training_time/60:.1f} minutes)")

        # Load best model
        if best_model_state:
            self.model.load_state_dict(best_model_state)

        return self.model

def main():
    # Check for CUDA
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f"Using device: {device}")

    # Load massive dataset
    print("Loading massive CodeSearchNet dataset...")
    try:
        massive_dataset = torch.load('massive_codesearchnet_dataset.pt', weights_only=False)
        print(f"Loaded {len(massive_dataset)} examples")

        # Check if dataset contains dictionaries (raw data) or PyG Data objects
        if len(massive_dataset) > 0 and isinstance(massive_dataset[0], dict):
            print("Dataset contains raw dictionaries, converting to PyG Data objects...")
            from torch_geometric.data import Data
            from torch_geometric.utils import from_networkx
            import networkx as nx
            import ast

            # Node type mapping (same as in create_massive_dataset.py)
            NODE_TYPES = {
                'Module': 0, 'FunctionDef': 1, 'ClassDef': 2, 'Return': 3, 'Assign': 4,
                'If': 5, 'For': 6, 'While': 7, 'Call': 8, 'Name': 9, 'Constant': 10,
                'BinOp': 11, 'Compare': 12, 'List': 13, 'Dict': 14, 'Attribute': 15,
                'Expr': 16, 'Import': 17, 'ImportFrom': 18, 'With': 19, 'Try': 20,
                'ExceptHandler': 21, 'Raise': 22, 'Assert': 23, 'Delete': 24, 'AugAssign': 25,
                'AnnAssign': 26, 'AsyncFunctionDef': 27, 'AsyncFor': 28, 'AsyncWith': 29,
                'Await': 30, 'Yield': 31, 'YieldFrom': 32, 'Global': 33, 'Nonlocal': 34,
                'Pass': 35, 'Break': 36, 'Continue': 37, 'Slice': 38, 'ExtSlice': 39,
                'Index': 40, 'Lambda': 41, 'Ellipsis': 42, 'Starred': 43, 'Set': 44,
                'SetComp': 45, 'DictComp': 46, 'ListComp': 47, 'GeneratorExp': 48
            }

            def ast_to_graph(ast_tree, max_nodes=100):
                """Convert AST to NetworkX graph with node features."""
                G = nx.DiGraph()
                node_id = 0
                node_features = {}

                def traverse_ast(node, parent_id=None):
                    nonlocal node_id
                    if node_id >= max_nodes:
                        return

                    # Create node features
                    node_type = type(node).__name__
                    node_type_id = NODE_TYPES.get(node_type, len(NODE_TYPES))

                    # Extract additional features
                    features = [float(node_type_id)]

                    # Add text content for certain node types
                    if hasattr(node, 'name') and node.name is not None:
                        features.extend([float(ord(c)) if c.isascii() else 0.0 for c in str(node.name)[:10].ljust(10)])
                    elif hasattr(node, 'id') and node.id is not None:
                        features.extend([float(ord(c)) if c.isascii() else 0.0 for c in str(node.id)[:10].ljust(10)])
                    elif hasattr(node, 'value') and node.value is not None and isinstance(node.value, str):
                        features.extend([float(ord(c)) if c.isascii() else 0.0 for c in str(node.value)[:10].ljust(10)])
                    elif hasattr(node, 'value') and node.value is not None and isinstance(node.value, (int, float)):
                        features.extend([float(node.value) if abs(float(node.value)) < 1000 else 0.0] + [0.0]*9)
                    else:
                        features.extend([0.0] * 10)

                    # Pad features to fixed size
                    while len(features) < 11:
                        features.append(0.0)

                    node_features[node_id] = features
                    current_id = node_id
                    node_id += 1

                    # Add edge to parent
                    if parent_id is not None:
                        G.add_edge(parent_id, current_id)

                    # Recursively traverse children
                    for child in ast.iter_child_nodes(node):
                        traverse_ast(child, current_id)

                traverse_ast(ast_tree)
                return G, node_features

            # Convert dictionaries to PyG Data objects
            pyg_dataset = []
            for i, example in enumerate(massive_dataset):
                if i % 10000 == 0:
                    print(f"Converting example {i}/{len(massive_dataset)}...")

                code = example['code']
                label = example['label']

                try:
                    ast_tree = ast.parse(code)
                    graph, node_features = ast_to_graph(ast_tree, max_nodes=100)

                    if len(graph.nodes) > 0:
                        # Convert to PyTorch Geometric format
                        data = from_networkx(graph)
                        data.x = torch.tensor(list(node_features.values()), dtype=torch.float)
                        data.y = torch.tensor([label], dtype=torch.long)
                        pyg_dataset.append(data)
                except:
                    continue

            massive_dataset = pyg_dataset
            print(f"Converted to {len(massive_dataset)} PyG Data objects")

            # Save the converted dataset
            torch.save(massive_dataset, 'massive_codesearchnet_dataset_converted.pt')
            print("Saved converted dataset as massive_codesearchnet_dataset_converted.pt")

    except FileNotFoundError:
        print("Massive dataset not found! Run 'python src/create_massive_dataset.py' first.")
        return

    # Analyze class distribution
    vuln_count = sum(1 for d in massive_dataset if d.y.item() == 1)
    safe_count = len(massive_dataset) - vuln_count
    print(f"Dataset composition: {vuln_count} vulnerable, {safe_count} safe")
    print(".3f")

    # Calculate class weights for imbalanced dataset
    total_samples = len(massive_dataset)
    class_weights = [
        total_samples / (2 * safe_count),      # weight for safe (class 0)
        total_samples / (2 * vuln_count)       # weight for vulnerable (class 1)
    ]
    print(f"Class weights: Safe={class_weights[0]:.2f}, Vulnerable={class_weights[1]:.2f}")
    print(f"Effective weight ratio: 1:{class_weights[1]/class_weights[0]:.1f}")

    # Stratified split
    vulnerable_data = [d for d in massive_dataset if d.y.item() == 1]
    safe_data = [d for d in massive_dataset if d.y.item() == 0]

    # Use smaller validation/test sets for speed
    vuln_train, vuln_temp = train_test_split(vulnerable_data, train_size=0.8, random_state=42)
    vuln_val, vuln_test = train_test_split(vuln_temp, train_size=0.5, random_state=42)

    safe_train, safe_temp = train_test_split(safe_data, train_size=0.8, random_state=42)
    safe_val, safe_test = train_test_split(safe_temp, train_size=0.5, random_state=42)

    # Combine
    train_data = vuln_train + safe_train
    val_data = vuln_val + safe_val
    test_data = vuln_test + safe_test

    # Shuffle
    import random
    random.shuffle(train_data)
    random.shuffle(val_data)
    random.shuffle(test_data)

    print(f"Split sizes: Train={len(train_data)}, Val={len(val_data)}, Test={len(test_data)}")

    # Create data loaders
    batch_size = 64  # Larger batch size for massive dataset
    train_loader = DataLoader(train_data, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_data, batch_size=batch_size, shuffle=False)
    test_loader = DataLoader(test_data, batch_size=batch_size, shuffle=False)

    # Get number of node features
    sample_data = massive_dataset[0]
    num_node_features = sample_data.x.shape[1]
    print(f"Node features: {num_node_features}")

    # Initialize model (deeper for massive dataset)
    model = VulnerabilityGNN(num_node_features=num_node_features, hidden_channels=128)
    trainer = MassiveDatasetTrainer(model, device, class_weights=class_weights)

    # Train model
    print("\nStarting training on massive dataset...")
    trained_model = trainer.train(train_loader, val_loader, num_epochs=20, patience=5)

    # Final evaluation on test set
    print("\nEvaluating on test set...")
    eval_start_time = time.time()
    test_results = trainer.validate(test_loader)
    test_loss, test_acc, test_prec, test_rec, test_f1, test_prec_per_class, test_rec_per_class, test_f1_per_class = test_results
    eval_time = time.time() - eval_start_time
    print(f"Evaluation completed in {eval_time:.1f} seconds")

    print("\nMassive Dataset Results:")
    print(f"Loss: {test_loss:.4f}")
    print(f"Accuracy: {test_acc:.4f}")
    print(f"Precision: {test_prec:.4f}")
    print(f"Recall: {test_rec:.4f}")
    print(f"F1-Score: {test_f1:.4f}")
    print(f"Per-class F1: Safe={test_f1_per_class[0]:.4f}, Vulnerable={test_f1_per_class[1]:.4f}")
    print(f"Per-class Precision: Safe={test_prec_per_class[0]:.4f}, Vulnerable={test_prec_per_class[1]:.4f}")
    print(f"Per-class Recall: Safe={test_rec_per_class[0]:.4f}, Vulnerable={test_rec_per_class[1]:.4f}")

    # Save trained model
    torch.save(trained_model.state_dict(), 'massive_vulnerability_gnn_model.pt')
    print("Massive model saved to massive_vulnerability_gnn_model.pt")

if __name__ == '__main__':
    main()