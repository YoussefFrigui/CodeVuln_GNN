import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GCNConv, GATConv, global_mean_pool, global_max_pool
from torch_geometric.data import DataLoader
from torch.optim import Adam
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import numpy as np

class VulnerabilityGNN(nn.Module):
    """Graph Neural Network for Code Vulnerability Detection."""

    def __init__(self, num_node_features, hidden_channels=64, num_classes=2, dropout=0.5):
        super(VulnerabilityGNN, self).__init__()

        # GCN layers
        self.conv1 = GCNConv(num_node_features, hidden_channels)
        self.conv2 = GCNConv(hidden_channels, hidden_channels)
        self.conv3 = GCNConv(hidden_channels, hidden_channels)

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

class GNNTrainer:
    """Trainer class for the Vulnerability GNN."""

    def __init__(self, model, device='cpu'):
        self.model = model.to(device)
        self.device = device
        self.optimizer = Adam(model.parameters(), lr=0.001, weight_decay=5e-4)
        self.criterion = nn.CrossEntropyLoss()

    def train_epoch(self, train_loader):
        self.model.train()
        total_loss = 0
        correct = 0
        total = 0

        for data in train_loader:
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

        return total_loss / len(train_loader), correct / total

    def validate(self, val_loader):
        self.model.eval()
        total_loss = 0
        y_true = []
        y_pred = []

        with torch.no_grad():
            for data in val_loader:
                data = data.to(self.device)
                out = self.model(data.x, data.edge_index, data.batch)
                loss = self.criterion(out, data.y.squeeze())

                total_loss += loss.item()
                pred = out.argmax(dim=1)

                y_true.extend(data.y.squeeze().cpu().numpy())
                y_pred.extend(pred.cpu().numpy())

        accuracy = accuracy_score(y_true, y_pred)
        precision = precision_score(y_true, y_pred, average='weighted', zero_division=0)
        recall = recall_score(y_true, y_pred, average='weighted', zero_division=0)
        f1 = f1_score(y_true, y_pred, average='weighted', zero_division=0)

        return total_loss / len(val_loader), accuracy, precision, recall, f1

    def train(self, train_loader, val_loader, num_epochs=50, patience=10):
        best_val_loss = float('inf')
        patience_counter = 0
        best_model_state = None

        for epoch in range(num_epochs):
            train_loss, train_acc = self.train_epoch(train_loader)
            val_loss, val_acc, val_prec, val_rec, val_f1 = self.validate(val_loader)

            print(f"Epoch {epoch+1:03d}: "
                  f"Train Loss: {train_loss:.4f}, Train Acc: {train_acc:.4f} | "
                  f"Val Loss: {val_loss:.4f}, Val Acc: {val_acc:.4f}, "
                  f"Val F1: {val_f1:.4f}")

            # Early stopping
            if val_loss < best_val_loss:
                best_val_loss = val_loss
                patience_counter = 0
                best_model_state = self.model.state_dict()
            else:
                patience_counter += 1
                if patience_counter >= patience:
                    print(f"Early stopping at epoch {epoch+1}")
                    break

        # Load best model
        if best_model_state:
            self.model.load_state_dict(best_model_state)

        return self.model

def main():
    # Check for CUDA
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f"Using device: {device}")

    # Load processed data and splits
    try:
        processed_data = torch.load('outputs/datasets/processed_graphs.pt', weights_only=False)
        data_splits = torch.load('outputs/datasets/data_splits.pt', weights_only=False)
        train_data = data_splits['train_data']
        val_data = data_splits['val_data']
        test_data = data_splits['test_data']
    except FileNotFoundError:
        print("Processed data not found. Please run preprocess_data.py first.")
        return

    # Create data loaders
    batch_size = 32
    train_loader = DataLoader(train_data, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_data, batch_size=batch_size, shuffle=False)
    test_loader = DataLoader(test_data, batch_size=batch_size, shuffle=False)

    # Get number of node features
    sample_data = processed_data[0]
    num_node_features = sample_data.x.shape[1]

    # Initialize model
    model = VulnerabilityGNN(num_node_features=num_node_features)
    trainer = GNNTrainer(model, str(device))

    # Train model
    print("Starting training...")
    trained_model = trainer.train(train_loader, val_loader, num_epochs=50)

    # Final evaluation on test set
    print("\nEvaluating on test set...")
    test_loss, test_acc, test_prec, test_rec, test_f1 = trainer.validate(test_loader)

    print(f"Test Results:")
    print(f"Loss: {test_loss:.4f}")
    print(f"Accuracy: {test_acc:.4f}")
    print(f"Precision: {test_prec:.4f}")
    print(f"Recall: {test_rec:.4f}")
    print(f"F1-Score: {test_f1:.4f}")

    # Save trained model
    torch.save(trained_model.state_dict(), 'outputs/models/vulnerability_gnn_model.pt')
    print("Model saved to outputs/models/vulnerability_gnn_model.pt")

if __name__ == '__main__':
    main()
