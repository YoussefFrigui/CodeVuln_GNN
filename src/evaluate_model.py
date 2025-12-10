"""
Comprehensive Model Evaluation Script

Evaluates the trained GNN model on multiple dataset splits (train, validation, test)
and generates detailed metrics, confusion matrices, and visualization charts.
"""

import os
import torch
from torch_geometric.data import DataLoader
from sklearn.metrics import (
    classification_report, confusion_matrix, roc_curve, auc,
    precision_recall_curve, average_precision_score, f1_score,
    accuracy_score, precision_score, recall_score
)
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from tqdm import tqdm
import sys
import json
from pathlib import Path
from datetime import datetime

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent))

# Create output directory
RESULTS_DIR = Path("outputs/results")
RESULTS_DIR.mkdir(parents=True, exist_ok=True)


def load_model_and_data(model_path=None, data_path='outputs/datasets/data_splits.pt'):
    """Load trained model and all data splits."""
    import yaml
    
    from modeling.model import VulnerabilityGNN

    with open('configs/base_config.yaml', 'r') as f:
        config = yaml.safe_load(f)
    
    if model_path is None:
        model_path = config["output"]["model_save_path"]

    # Initialize model with correct parameters
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
    
    print(f"Loading model from: {model_path}")
    model.load_state_dict(torch.load(model_path, weights_only=False))
    model.eval()

    # Load all data splits
    data_splits = torch.load(data_path, weights_only=False)
    
    datasets = {
        'train': data_splits['train_data'],
        'validation': data_splits['val_data'],
        'test': data_splits['test_data'],
    }
    
    # Print dataset compositions
    print("\n📊 Dataset Compositions:")
    for name, data in datasets.items():
        labels = [d.y.item() for d in data]
        num_safe = sum(1 for l in labels if l == 0)
        num_vuln = sum(1 for l in labels if l == 1)
        print(f"  {name.capitalize():12s}: {len(data):,} samples ({num_safe:,} safe, {num_vuln:,} vulnerable)")

    return model, datasets, config


def evaluate_on_split(model, data, device='cpu', batch_size=32):
    """Evaluate model on a specific data split."""
    model = model.to(device)
    model.eval()
    
    loader = DataLoader(data, batch_size=batch_size, shuffle=False)

    y_true = []
    y_pred = []
    y_prob = []

    with torch.no_grad():
        for batch in tqdm(loader, desc="Evaluating", leave=False):
            batch = batch.to(device)
            out = model(batch.x, batch.edge_index, batch.batch)
            prob = torch.softmax(out, dim=1)
            pred = out.argmax(dim=1)

            y_true.extend(batch.y.squeeze().cpu().numpy())
            y_pred.extend(pred.cpu().numpy())
            y_prob.extend(prob.cpu().numpy())

    return np.array(y_true), np.array(y_pred), np.array(y_prob)


def compute_metrics(y_true, y_pred, y_prob):
    """Compute comprehensive metrics."""
    metrics = {
        'accuracy': accuracy_score(y_true, y_pred),
        'precision': precision_score(y_true, y_pred, zero_division=0),
        'recall': recall_score(y_true, y_pred, zero_division=0),
        'f1': f1_score(y_true, y_pred, zero_division=0),
        'precision_weighted': precision_score(y_true, y_pred, average='weighted', zero_division=0),
        'recall_weighted': recall_score(y_true, y_pred, average='weighted', zero_division=0),
        'f1_weighted': f1_score(y_true, y_pred, average='weighted', zero_division=0),
    }
    
    # Confusion matrix values
    cm = confusion_matrix(y_true, y_pred)
    if cm.shape == (2, 2):
        tn, fp, fn, tp = cm.ravel()
        metrics['true_negatives'] = int(tn)
        metrics['false_positives'] = int(fp)
        metrics['false_negatives'] = int(fn)
        metrics['true_positives'] = int(tp)
        metrics['specificity'] = tn / (tn + fp) if (tn + fp) > 0 else 0
        metrics['false_positive_rate'] = fp / (fp + tn) if (fp + tn) > 0 else 0
        metrics['false_negative_rate'] = fn / (fn + tp) if (fn + tp) > 0 else 0
    
    # ROC-AUC
    if len(np.unique(y_true)) == 2:
        fpr, tpr, _ = roc_curve(y_true, y_prob[:, 1])
        metrics['roc_auc'] = auc(fpr, tpr)
        metrics['average_precision'] = average_precision_score(y_true, y_prob[:, 1])
    
    return metrics, cm


def plot_confusion_matrix(cm, split_name, save_path):
    """Plot and save confusion matrix."""
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=['Safe', 'Vulnerable'],
                yticklabels=['Safe', 'Vulnerable'],
                annot_kws={'size': 14})
    plt.title(f'Confusion Matrix - {split_name.capitalize()} Set', fontsize=14)
    plt.ylabel('True Label', fontsize=12)
    plt.xlabel('Predicted Label', fontsize=12)
    plt.tight_layout()
    plt.savefig(save_path, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"  ✓ Saved: {save_path}")


def plot_roc_curve(y_true, y_prob, split_name, save_path):
    """Plot and save ROC curve."""
    if len(np.unique(y_true)) != 2:
        return
    
    fpr, tpr, _ = roc_curve(y_true, y_prob[:, 1])
    roc_auc = auc(fpr, tpr)
    
    plt.figure(figsize=(8, 6))
    plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (AUC = {roc_auc:.3f})')
    plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--', label='Random Classifier')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate', fontsize=12)
    plt.ylabel('True Positive Rate', fontsize=12)
    plt.title(f'ROC Curve - {split_name.capitalize()} Set', fontsize=14)
    plt.legend(loc="lower right")
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(save_path, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"  ✓ Saved: {save_path}")


def plot_precision_recall_curve(y_true, y_prob, split_name, save_path):
    """Plot and save Precision-Recall curve."""
    if len(np.unique(y_true)) != 2:
        return
    
    precision, recall, _ = precision_recall_curve(y_true, y_prob[:, 1])
    avg_precision = average_precision_score(y_true, y_prob[:, 1])
    
    plt.figure(figsize=(8, 6))
    plt.plot(recall, precision, color='green', lw=2, label=f'PR curve (AP = {avg_precision:.3f})')
    plt.axhline(y=np.mean(y_true), color='navy', linestyle='--', label=f'Baseline (prevalence = {np.mean(y_true):.3f})')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('Recall', fontsize=12)
    plt.ylabel('Precision', fontsize=12)
    plt.title(f'Precision-Recall Curve - {split_name.capitalize()} Set', fontsize=14)
    plt.legend(loc="upper right")
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(save_path, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"  ✓ Saved: {save_path}")


def plot_score_distribution(y_true, y_prob, split_name, save_path):
    """Plot vulnerability score distribution by class."""
    plt.figure(figsize=(10, 6))
    
    safe_scores = y_prob[y_true == 0, 1]
    vuln_scores = y_prob[y_true == 1, 1]
    
    plt.hist(safe_scores, bins=50, alpha=0.6, label=f'Safe (n={len(safe_scores)})', color='green')
    plt.hist(vuln_scores, bins=50, alpha=0.6, label=f'Vulnerable (n={len(vuln_scores)})', color='red')
    plt.axvline(x=0.5, color='black', linestyle='--', label='Default Threshold (0.5)')
    plt.axvline(x=0.35, color='orange', linestyle='--', label='Sensitive Threshold (0.35)')
    
    plt.xlabel('Vulnerability Score', fontsize=12)
    plt.ylabel('Count', fontsize=12)
    plt.title(f'Score Distribution by Class - {split_name.capitalize()} Set', fontsize=14)
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(save_path, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"  ✓ Saved: {save_path}")


def plot_metrics_comparison(all_metrics, save_path):
    """Plot metrics comparison across all splits."""
    splits = list(all_metrics.keys())
    metrics_to_plot = ['accuracy', 'precision', 'recall', 'f1', 'roc_auc']
    
    x = np.arange(len(metrics_to_plot))
    width = 0.25
    
    fig, ax = plt.subplots(figsize=(12, 6))
    
    colors = {'train': '#2ecc71', 'validation': '#3498db', 'test': '#e74c3c'}
    
    for i, split in enumerate(splits):
        values = [all_metrics[split].get(m, 0) for m in metrics_to_plot]
        offset = (i - 1) * width
        bars = ax.bar(x + offset, values, width, label=split.capitalize(), color=colors.get(split, 'gray'))
        
        # Add value labels on bars
        for bar, val in zip(bars, values):
            ax.annotate(f'{val:.3f}',
                       xy=(bar.get_x() + bar.get_width() / 2, bar.get_height()),
                       xytext=(0, 3),
                       textcoords="offset points",
                       ha='center', va='bottom', fontsize=8)
    
    ax.set_xlabel('Metric', fontsize=12)
    ax.set_ylabel('Score', fontsize=12)
    ax.set_title('Model Performance Across Dataset Splits', fontsize=14)
    ax.set_xticks(x)
    ax.set_xticklabels([m.replace('_', ' ').title() for m in metrics_to_plot])
    ax.legend()
    ax.set_ylim(0, 1.1)
    ax.grid(True, alpha=0.3, axis='y')
    
    plt.tight_layout()
    plt.savefig(save_path, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"  ✓ Saved: {save_path}")


def plot_error_analysis(y_true, y_pred, split_name, save_path):
    """Plot error analysis chart."""
    cm = confusion_matrix(y_true, y_pred)
    
    if cm.shape != (2, 2):
        return
    
    tn, fp, fn, tp = cm.ravel()
    
    categories = ['True\nNegatives\n(Correct Safe)', 'False\nPositives\n(False Alarm)', 
                  'False\nNegatives\n(Missed Vuln)', 'True\nPositives\n(Correct Vuln)']
    values = [tn, fp, fn, tp]
    colors = ['#2ecc71', '#f39c12', '#e74c3c', '#27ae60']
    
    fig, ax = plt.subplots(figsize=(10, 6))
    bars = ax.bar(categories, values, color=colors)
    
    # Add value labels
    for bar, val in zip(bars, values):
        ax.annotate(f'{val:,}',
                   xy=(bar.get_x() + bar.get_width() / 2, bar.get_height()),
                   xytext=(0, 3),
                   textcoords="offset points",
                   ha='center', va='bottom', fontsize=12, fontweight='bold')
    
    ax.set_ylabel('Count', fontsize=12)
    ax.set_title(f'Prediction Breakdown - {split_name.capitalize()} Set', fontsize=14)
    ax.grid(True, alpha=0.3, axis='y')
    
    plt.tight_layout()
    plt.savefig(save_path, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"  ✓ Saved: {save_path}")


def print_evaluation_report(split_name, metrics, cm):
    """Print detailed evaluation metrics for a split."""
    print(f"\n{'='*60}")
    print(f"📊 {split_name.upper()} SET EVALUATION")
    print('='*60)
    
    print(f"\n📈 Key Metrics:")
    print(f"   Accuracy:    {metrics['accuracy']:.4f}")
    print(f"   Precision:   {metrics['precision']:.4f}")
    print(f"   Recall:      {metrics['recall']:.4f}")
    print(f"   F1 Score:    {metrics['f1']:.4f}")
    if 'roc_auc' in metrics:
        print(f"   ROC-AUC:     {metrics['roc_auc']:.4f}")
    if 'average_precision' in metrics:
        print(f"   Avg Prec:    {metrics['average_precision']:.4f}")
    
    print(f"\n📋 Confusion Matrix:")
    print(f"                  Predicted")
    print(f"                  Safe    Vuln")
    print(f"   Actual Safe   {cm[0,0]:5d}   {cm[0,1]:5d}")
    print(f"   Actual Vuln   {cm[1,0]:5d}   {cm[1,1]:5d}")
    
    if 'true_positives' in metrics:
        print(f"\n🎯 Error Analysis:")
        print(f"   True Positives (correct vulnerable):  {metrics['true_positives']:,}")
        print(f"   True Negatives (correct safe):        {metrics['true_negatives']:,}")
        print(f"   False Positives (false alarms):       {metrics['false_positives']:,}")
        print(f"   False Negatives (missed vulnerabilities): {metrics['false_negatives']:,}")
        print(f"\n   Specificity (TNR):     {metrics['specificity']:.4f}")
        print(f"   False Positive Rate:   {metrics['false_positive_rate']:.4f}")
        print(f"   False Negative Rate:   {metrics['false_negative_rate']:.4f}")


def evaluate_model_comprehensive(model_path=None, data_path='outputs/datasets/data_splits.pt'):
    """Run comprehensive evaluation on all splits."""
    print("\n" + "="*60)
    print("🔍 COMPREHENSIVE MODEL EVALUATION")
    print("="*60)
    
    # Load model and data
    model, datasets, config = load_model_and_data(model_path, data_path)
    device = 'cuda' if torch.cuda.is_available() else 'cpu'
    print(f"\n🖥️  Using device: {device}")
    
    # Timestamp for this evaluation run
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Store all results
    all_metrics = {}
    all_results = {}
    
    # Evaluate each split
    for split_name, data in datasets.items():
        print(f"\n{'─'*40}")
        print(f"Evaluating {split_name} set ({len(data):,} samples)...")
        
        y_true, y_pred, y_prob = evaluate_on_split(model, data, device)
        metrics, cm = compute_metrics(y_true, y_pred, y_prob)
        
        all_metrics[split_name] = metrics
        all_results[split_name] = {
            'y_true': y_true,
            'y_pred': y_pred,
            'y_prob': y_prob,
            'cm': cm,
        }
        
        # Print report
        print_evaluation_report(split_name, metrics, cm)
        
        # Generate charts for this split
        print(f"\n📊 Generating charts for {split_name} set...")
        
        plot_confusion_matrix(
            cm, split_name, 
            RESULTS_DIR / f"confusion_matrix_{split_name}.png"
        )
        plot_roc_curve(
            y_true, y_prob, split_name,
            RESULTS_DIR / f"roc_curve_{split_name}.png"
        )
        plot_precision_recall_curve(
            y_true, y_prob, split_name,
            RESULTS_DIR / f"pr_curve_{split_name}.png"
        )
        plot_score_distribution(
            y_true, y_prob, split_name,
            RESULTS_DIR / f"score_distribution_{split_name}.png"
        )
        plot_error_analysis(
            y_true, y_pred, split_name,
            RESULTS_DIR / f"error_analysis_{split_name}.png"
        )
    
    # Generate comparison chart
    print(f"\n📊 Generating comparison charts...")
    plot_metrics_comparison(all_metrics, RESULTS_DIR / "metrics_comparison.png")
    
    # Save metrics to JSON
    metrics_path = RESULTS_DIR / f"evaluation_metrics_{timestamp}.json"
    
    # Convert numpy types to Python types for JSON serialization
    def convert_to_serializable(obj):
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        elif isinstance(obj, (np.int32, np.int64)):
            return int(obj)
        elif isinstance(obj, (np.float32, np.float64)):
            return float(obj)
        return obj
    
    serializable_metrics = {
        split: {k: convert_to_serializable(v) for k, v in metrics.items()}
        for split, metrics in all_metrics.items()
    }
    serializable_metrics['timestamp'] = timestamp
    serializable_metrics['model_path'] = str(model_path or config["output"]["model_save_path"])
    
    with open(metrics_path, 'w') as f:
        json.dump(serializable_metrics, f, indent=2)
    print(f"  ✓ Saved: {metrics_path}")
    
    # Print summary
    print("\n" + "="*60)
    print("📋 EVALUATION SUMMARY")
    print("="*60)
    print(f"\n{'Split':<12} {'Accuracy':>10} {'Precision':>10} {'Recall':>10} {'F1':>10} {'ROC-AUC':>10}")
    print("-"*62)
    for split_name, metrics in all_metrics.items():
        print(f"{split_name.capitalize():<12} "
              f"{metrics['accuracy']:>10.4f} "
              f"{metrics['precision']:>10.4f} "
              f"{metrics['recall']:>10.4f} "
              f"{metrics['f1']:>10.4f} "
              f"{metrics.get('roc_auc', 0):>10.4f}")
    
    print(f"\n📁 All results saved to: {RESULTS_DIR}")
    print("="*60)
    
    return all_metrics, all_results


# Keep simple main for backward compatibility
def main():
    evaluate_model_comprehensive()


if __name__ == '__main__':
    main()