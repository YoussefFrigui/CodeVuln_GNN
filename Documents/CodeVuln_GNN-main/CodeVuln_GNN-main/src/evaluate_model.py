import torch
from torch_geometric.data import DataLoader
from sklearn.metrics import classification_report, confusion_matrix
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

def load_model_and_data(model_path='outputs/models/vulnerability_gnn_model.pt', data_path='outputs/datasets/data_splits.pt'):
    """Load trained model and test data."""
    # Load model
    from train_gnn import VulnerabilityGNN  # Import the model class

    # Get number of features (this should match training)
    processed_data = torch.load('outputs/datasets/processed_graphs.pt', weights_only=False)
    num_node_features = processed_data[0].x.shape[1]

    model = VulnerabilityGNN(num_node_features=num_node_features)
    model.load_state_dict(torch.load(model_path))
    model.eval()

    # Load data splits and create test loader
    data_splits = torch.load(data_path, weights_only=False)
    test_data = data_splits['test_data']
    test_loader = DataLoader(test_data, batch_size=32, shuffle=False)

    return model, test_loader

def evaluate_model(model, test_loader, device='cpu'):
    """Comprehensive model evaluation."""
    model = model.to(device)
    model.eval()

    y_true = []
    y_pred = []
    y_prob = []

    with torch.no_grad():
        for data in test_loader:
            data = data.to(device)
            out = model(data.x, data.edge_index, data.batch)

            prob = torch.softmax(out, dim=1)
            pred = out.argmax(dim=1)

            y_true.extend(data.y.squeeze().cpu().numpy())
            y_pred.extend(pred.cpu().numpy())
            y_prob.extend(prob.cpu().numpy())

    y_true = np.array(y_true)
    y_pred = np.array(y_pred)
    y_prob = np.array(y_prob)

    return y_true, y_pred, y_prob

def print_evaluation_report(y_true, y_pred, y_prob):
    """Print detailed evaluation metrics."""
    print("=== Model Evaluation Report ===\n")

    # Classification report
    print("Classification Report:")
    print(classification_report(y_true, y_pred, target_names=['Safe', 'Vulnerable']))

    # Confusion matrix
    cm = confusion_matrix(y_true, y_pred)
    print("\nConfusion Matrix:")
    print(cm)

    # Additional metrics
    accuracy = np.mean(y_true == y_pred)
    print(".4f")

    # Class-specific metrics
    safe_correct = cm[0, 0] / cm[0].sum() if cm[0].sum() > 0 else 0
    vuln_correct = cm[1, 1] / cm[1].sum() if cm[1].sum() > 0 else 0

    print(".4f")
    print(".4f")

    return cm

def plot_confusion_matrix(cm, save_path='outputs/results/confusion_matrix.png'):
    """Plot and save confusion matrix."""
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=['Safe', 'Vulnerable'],
                yticklabels=['Safe', 'Vulnerable'])
    plt.title('Confusion Matrix')
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    plt.tight_layout()
    plt.savefig(save_path, dpi=300, bbox_inches='tight')
    plt.show()
    print(f"Confusion matrix saved to {save_path}")

def analyze_errors(y_true, y_pred, test_loader):
    """Analyze prediction errors."""
    print("\n=== Error Analysis ===")

    errors = y_true != y_pred
    error_indices = np.where(errors)[0]

    print(f"Total errors: {len(error_indices)} out of {len(y_true)} samples")
    print(".2%")

    # Error types
    false_positives = np.sum((y_pred == 1) & (y_true == 0))
    false_negatives = np.sum((y_pred == 0) & (y_true == 1))

    print(f"False Positives (predicted vulnerable, actually safe): {false_positives}")
    print(f"False Negatives (predicted safe, actually vulnerable): {false_negatives}")

    if len(error_indices) > 0:
        print(f"\nSample error analysis:")
        for i in error_indices[:5]:  # Show first 5 errors
            true_label = "Vulnerable" if y_true[i] == 1 else "Safe"
            pred_label = "Vulnerable" if y_pred[i] == 1 else "Safe"
            print(f"Sample {i}: True={true_label}, Predicted={pred_label}")

def main():
    print("Loading model and data...")
    model, test_loader = load_model_and_data()

    print("Evaluating model...")
    y_true, y_pred, y_prob = evaluate_model(model, test_loader)

    # Print evaluation report
    cm = print_evaluation_report(y_true, y_pred, y_prob)

    # Plot confusion matrix
    try:
        plot_confusion_matrix(cm)
    except ImportError:
        print("Matplotlib/seaborn not available for plotting")

    # Error analysis
    analyze_errors(y_true, y_pred, test_loader)

    print("\n=== Summary ===")
    print("Model evaluation complete!")
    print("Key insights:")
    print("- Focus on reducing false negatives (missed vulnerabilities)")
    print("- Consider class imbalance in training data")
    print("- May need more sophisticated features or larger model")

if __name__ == '__main__':
    main()
