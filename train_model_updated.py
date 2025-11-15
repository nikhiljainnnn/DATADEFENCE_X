import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (accuracy_score, classification_report, confusion_matrix, 
                             roc_auc_score, roc_curve, precision_recall_curve, auc)
import pickle
import warnings
import sys
import os
from datetime import datetime
import json

# Visualization imports
import matplotlib.pyplot as plt
import seaborn as sns
from matplotlib.patches import Rectangle

warnings.filterwarnings('ignore')

# Set style for beautiful plots
plt.style.use('seaborn-v0_8-darkgrid')
sns.set_palette("husl")

# Color codes for terminal output
class Colors:
    SUCCESS = '\033[92m'
    ERROR = '\033[91m'
    INFO = '\033[94m'
    WARNING = '\033[93m'
    RESET = '\033[0m'

def print_section(text):
    """Print section header"""
    print(f"\n{'='*70}\n{text}\n{'='*70}\n")

def print_status(text, status="info"):
    """Print status message with color"""
    colors = {
        'success': Colors.SUCCESS,
        'error': Colors.ERROR,
        'info': Colors.INFO,
        'warning': Colors.WARNING
    }
    color = colors.get(status, Colors.INFO)
    print(f"{color}[*] {text}{Colors.RESET}")


class FeatureMapper:
    
    # Real-time feature definitions (17 features)
    REALTIME_FEATURES = [
        'parent_suspicious',           # 0: Process parent-child relationship
        'cmdline_entropy',             # 1: Command line entropy
        'path_suspicious',             # 2: Suspicious path location
        'process_chain_depth',         # 3: Process ancestry depth
        'is_system_binary_misplaced',  # 4: System binary in wrong location
        'rwx_region_count',            # 5: RWX memory regions (CRITICAL)
        'private_memory_mb',           # 6: Private memory usage
        'is_hollowed',                 # 7: Process hollowing detected
        'remote_threads',              # 8: Remote thread injection
        'active_connections',          # 9: Active network connections
        'c2_beacon_score',             # 10: C2 beacon probability
        'dns_entropy',                 # 11: DNS query entropy
        'file_writes_per_min',         # 12: File write rate
        'registry_mods_per_min',       # 13: Registry modification rate
        'process_creates_per_min',     # 14: Process creation rate
        'api_calls_suspicious',        # 15: Suspicious API calls
        'total_events_5min'            # 16: Total events in 5 min window
    ]
    
    @staticmethod
    def map_volatility_to_realtime(X_volatility):
        n_samples = len(X_volatility)
        X_realtime = np.zeros((n_samples, 17))
        
        print_status("  → Mapping process features...", "info")
        
        # Feature 0: parent_suspicious (from process relationships)
        if 'pslist.nppid' in X_volatility.columns:
            X_realtime[:, 0] = (X_volatility['pslist.nppid'] > 15).astype(int)
        
        # Feature 1: cmdline_entropy (approximate from process diversity)
        if 'pslist.nproc' in X_volatility.columns:
            X_realtime[:, 1] = np.clip(X_volatility['pslist.nproc'] / 10.0, 0, 7)
        
        # Feature 2: path_suspicious (from module loading patterns)
        if 'ldrmodules.not_in_load' in X_volatility.columns:
            X_realtime[:, 2] = (X_volatility['ldrmodules.not_in_load'] > 0).astype(int)
        
        # Feature 3: process_chain_depth (from parent process count)
        if 'pslist.nppid' in X_volatility.columns:
            X_realtime[:, 3] = np.clip(X_volatility['pslist.nppid'] / 5.0, 1, 10)
        
        # Feature 4: is_system_binary_misplaced (from module inconsistencies)
        if 'ldrmodules.not_in_mem' in X_volatility.columns:
            X_realtime[:, 4] = (X_volatility['ldrmodules.not_in_mem'] > 0).astype(int)
        
        print_status("  → Mapping memory features...", "info")
        
        # Feature 5: rwx_region_count (CRITICAL - from malfind)
        if 'malfind.ninjections' in X_volatility.columns:
            X_realtime[:, 5] = X_volatility['malfind.ninjections']
        
        # Feature 6: private_memory_mb (from malfind commitCharge)
        if 'malfind.commitCharge' in X_volatility.columns:
            X_realtime[:, 6] = X_volatility['malfind.commitCharge'] / 1024.0
        
        # Feature 7: is_hollowed (from psxview hidden processes)
        if 'psxview.not_in_pslist' in X_volatility.columns:
            X_realtime[:, 7] = (X_volatility['psxview.not_in_pslist'] > 0).astype(int)
        
        # Feature 8: remote_threads (from malfind protection)
        if 'malfind.protection' in X_volatility.columns:
            X_realtime[:, 8] = X_volatility['malfind.protection']
        
        print_status("  → Mapping network features...", "info")
        
        # Feature 9: active_connections (from handles.nport)
        if 'handles.nport' in X_volatility.columns:
            X_realtime[:, 9] = X_volatility['handles.nport']
        
        # Feature 10: c2_beacon_score (derived from network + file activity)
        if 'handles.nport' in X_volatility.columns and 'handles.nfile' in X_volatility.columns:
            port_norm = np.clip(X_volatility['handles.nport'] / 100.0, 0, 1)
            file_norm = np.clip(X_volatility['handles.nfile'] / 1000.0, 0, 1)
            X_realtime[:, 10] = port_norm * file_norm
        
        # Feature 11: dns_entropy (approximate from handle diversity)
        if 'handles.nhandles' in X_volatility.columns:
            X_realtime[:, 11] = np.clip(X_volatility['handles.nhandles'] / 1000.0, 0, 7)
        
        print_status("  → Mapping behavioral features...", "info")
        
        # Feature 12: file_writes_per_min (from handles.nfile)
        if 'handles.nfile' in X_volatility.columns:
            X_realtime[:, 12] = np.clip(X_volatility['handles.nfile'] / 10.0, 0, 100)
        
        # Feature 13: registry_mods_per_min (from handles.nkey)
        if 'handles.nkey' in X_volatility.columns:
            X_realtime[:, 13] = np.clip(X_volatility['handles.nkey'] / 5.0, 0, 50)
        
        # Feature 14: process_creates_per_min (from pslist.nproc)
        if 'pslist.nproc' in X_volatility.columns:
            X_realtime[:, 14] = np.clip(X_volatility['pslist.nproc'] / 20.0, 0, 10)
        
        # Feature 15: api_calls_suspicious (from callbacks.nanonymous)
        if 'callbacks.nanonymous' in X_volatility.columns:
            X_realtime[:, 15] = X_volatility['callbacks.nanonymous']
        
        # Feature 16: total_events_5min (from handle activity)
        if 'handles.avg_handles_per_proc' in X_volatility.columns:
            X_realtime[:, 16] = np.clip(X_volatility['handles.avg_handles_per_proc'], 0, 500)
        
        print_status("  → Feature mapping complete", "success")
        
        return X_realtime


def plot_confusion_matrix(cm, model_name, save_path):
    """Plot beautiful confusion matrix heatmap"""
    fig, ax = plt.subplots(figsize=(10, 8))
    
    # Create heatmap
    sns.heatmap(cm, annot=True, fmt='d', cmap='RdYlGn_r', 
                square=True, linewidths=2, cbar_kws={'label': 'Count'},
                annot_kws={'size': 16, 'weight': 'bold'})
    
    # Labels
    ax.set_xlabel('Predicted Label', fontsize=14, fontweight='bold')
    ax.set_ylabel('True Label', fontsize=14, fontweight='bold')
    ax.set_title(f'Confusion Matrix - {model_name}', fontsize=16, fontweight='bold', pad=20)
    
    # Tick labels
    ax.set_xticklabels(['Benign', 'Malicious'], fontsize=12)
    ax.set_yticklabels(['Benign', 'Malicious'], fontsize=12, rotation=0)
    
    # Add metrics as text
    tn, fp, fn, tp = cm.ravel()
    total = tn + fp + fn + tp
    accuracy = (tp + tn) / total
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    metrics_text = f'Accuracy: {accuracy:.2%}\nPrecision: {precision:.2%}\nRecall: {recall:.2%}\nF1-Score: {f1:.2%}'
    plt.text(2.5, 0.5, metrics_text, fontsize=11, bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.8))
    
    plt.tight_layout()
    plt.savefig(save_path, dpi=300, bbox_inches='tight')
    plt.close()
    
    print_status(f"Confusion matrix saved: {save_path}", "success")


def plot_roc_curve(y_true, y_pred_proba, model_name, save_path):
    """Plot ROC curve"""
    fpr, tpr, thresholds = roc_curve(y_true, y_pred_proba)
    roc_auc = auc(fpr, tpr)
    
    fig, ax = plt.subplots(figsize=(10, 8))
    
    # Plot ROC curve
    ax.plot(fpr, tpr, color='darkorange', lw=3, label=f'ROC curve (AUC = {roc_auc:.4f})')
    ax.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--', label='Random Classifier')
    
    # Fill area under curve
    ax.fill_between(fpr, tpr, alpha=0.3, color='orange')
    
    ax.set_xlim([0.0, 1.0])
    ax.set_ylim([0.0, 1.05])
    ax.set_xlabel('False Positive Rate', fontsize=14, fontweight='bold')
    ax.set_ylabel('True Positive Rate', fontsize=14, fontweight='bold')
    ax.set_title(f'ROC Curve - {model_name}', fontsize=16, fontweight='bold', pad=20)
    ax.legend(loc="lower right", fontsize=12)
    ax.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(save_path, dpi=300, bbox_inches='tight')
    plt.close()
    
    print_status(f"ROC curve saved: {save_path}", "success")


def plot_precision_recall_curve(y_true, y_pred_proba, model_name, save_path):
    """Plot Precision-Recall curve"""
    precision, recall, thresholds = precision_recall_curve(y_true, y_pred_proba)
    pr_auc = auc(recall, precision)
    
    fig, ax = plt.subplots(figsize=(10, 8))
    
    ax.plot(recall, precision, color='blue', lw=3, label=f'PR curve (AUC = {pr_auc:.4f})')
    ax.fill_between(recall, precision, alpha=0.3, color='blue')
    
    ax.set_xlim([0.0, 1.0])
    ax.set_ylim([0.0, 1.05])
    ax.set_xlabel('Recall', fontsize=14, fontweight='bold')
    ax.set_ylabel('Precision', fontsize=14, fontweight='bold')
    ax.set_title(f'Precision-Recall Curve - {model_name}', fontsize=16, fontweight='bold', pad=20)
    ax.legend(loc="lower left", fontsize=12)
    ax.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(save_path, dpi=300, bbox_inches='tight')
    plt.close()
    
    print_status(f"Precision-Recall curve saved: {save_path}", "success")


def plot_feature_importance(feature_names, importances, model_name, save_path, top_n=15):
    """Plot feature importance"""
    # Sort features by importance
    indices = np.argsort(importances)[::-1][:top_n]
    
    fig, ax = plt.subplots(figsize=(12, 8))
    
    # Create bar plot
    colors = plt.cm.viridis(np.linspace(0.3, 0.9, top_n))
    bars = ax.barh(range(top_n), importances[indices], color=colors, edgecolor='black', linewidth=1.5)
    
    # Add value labels
    for i, (idx, bar) in enumerate(zip(indices, bars)):
        width = bar.get_width()
        ax.text(width, bar.get_y() + bar.get_height()/2, 
               f'{importances[idx]:.4f}', 
               ha='left', va='center', fontsize=10, fontweight='bold')
    
    ax.set_yticks(range(top_n))
    ax.set_yticklabels([feature_names[i] for i in indices], fontsize=11)
    ax.set_xlabel('Importance Score', fontsize=14, fontweight='bold')
    ax.set_title(f'Top {top_n} Feature Importance - {model_name}', fontsize=16, fontweight='bold', pad=20)
    ax.grid(True, alpha=0.3, axis='x')
    
    plt.tight_layout()
    plt.savefig(save_path, dpi=300, bbox_inches='tight')
    plt.close()
    
    print_status(f"Feature importance plot saved: {save_path}", "success")


def plot_training_metrics(train_acc, test_acc, cv_scores, model_name, save_path):
    """Plot training metrics comparison"""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))
    
    # Plot 1: Accuracy comparison
    metrics = ['Training', 'Testing', 'CV Mean']
    scores = [train_acc * 100, test_acc * 100, np.mean(cv_scores) * 100]
    colors_list = ['#2ecc71', '#3498db', '#e74c3c']
    
    bars = ax1.bar(metrics, scores, color=colors_list, edgecolor='black', linewidth=2)
    
    # Add value labels on bars
    for bar, score in zip(bars, scores):
        height = bar.get_height()
        ax1.text(bar.get_x() + bar.get_width()/2., height,
                f'{score:.2f}%',
                ha='center', va='bottom', fontsize=14, fontweight='bold')
    
    ax1.set_ylabel('Accuracy (%)', fontsize=14, fontweight='bold')
    ax1.set_title('Model Accuracy Comparison', fontsize=16, fontweight='bold')
    ax1.set_ylim([0, 105])
    ax1.grid(True, alpha=0.3, axis='y')
    ax1.axhline(y=90, color='red', linestyle='--', linewidth=2, alpha=0.5, label='90% threshold')
    ax1.legend(fontsize=11)
    
    # Plot 2: Cross-validation scores distribution
    ax2.boxplot([cv_scores * 100], widths=0.5, patch_artist=True,
                boxprops=dict(facecolor='lightblue', edgecolor='black', linewidth=2),
                medianprops=dict(color='red', linewidth=3),
                whiskerprops=dict(color='black', linewidth=2),
                capprops=dict(color='black', linewidth=2))
    
    # Add scatter points
    ax2.scatter([1] * len(cv_scores), cv_scores * 100, alpha=0.6, s=100, c='darkblue', edgecolors='black')
    
    ax2.set_ylabel('Accuracy (%)', fontsize=14, fontweight='bold')
    ax2.set_title('Cross-Validation Score Distribution', fontsize=16, fontweight='bold')
    ax2.set_xticklabels(['5-Fold CV'], fontsize=12)
    ax2.grid(True, alpha=0.3, axis='y')
    
    # Add statistics text
    cv_mean = np.mean(cv_scores) * 100
    cv_std = np.std(cv_scores) * 100
    stats_text = f'Mean: {cv_mean:.2f}%\nStd: {cv_std:.2f}%\nMin: {np.min(cv_scores)*100:.2f}%\nMax: {np.max(cv_scores)*100:.2f}%'
    ax2.text(1.3, cv_mean, stats_text, fontsize=10, 
            bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.8))
    
    plt.suptitle(f'{model_name} - Training Metrics', fontsize=18, fontweight='bold', y=1.02)
    plt.tight_layout()
    plt.savefig(save_path, dpi=300, bbox_inches='tight')
    plt.close()
    
    print_status(f"Training metrics plot saved: {save_path}", "success")


def plot_accuracy_curves(model, X_train, X_test, y_train, y_test, model_name, save_path):
    """Plot training accuracy evolution with different dataset sizes"""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))
    
    # Plot 1: Accuracy vs Training Set Size (Learning Curve)
    train_sizes = np.linspace(0.1, 1.0, 10)
    train_scores = []
    test_scores = []
    
    print_status(f"  Computing learning curve for {model_name}...", "info")
    
    for size in train_sizes:
        n_samples = int(len(X_train) * size)
        if n_samples < 100:
            continue
            
        # Sample data
        indices = np.random.choice(len(X_train), n_samples, replace=False)
        X_subset = X_train.iloc[indices] if hasattr(X_train, 'iloc') else X_train[indices]
        y_subset = y_train.iloc[indices] if hasattr(y_train, 'iloc') else y_train[indices]
        
        # Train on subset
        model.fit(X_subset, y_subset)
        
        # Evaluate
        train_pred = model.predict(X_subset)
        test_pred = model.predict(X_test)
        
        train_acc = accuracy_score(y_subset, train_pred) * 100
        test_acc = accuracy_score(y_test, test_pred) * 100
        
        train_scores.append(train_acc)
        test_scores.append(test_acc)
    
    # Plot learning curves
    sizes_plot = [int(len(X_train) * s) for s in train_sizes[:len(train_scores)]]
    
    ax1.plot(sizes_plot, train_scores, 'o-', color='#2ecc71', linewidth=3, 
             markersize=8, label='Training Accuracy', markeredgecolor='black', markeredgewidth=2)
    ax1.plot(sizes_plot, test_scores, 's-', color='#e74c3c', linewidth=3, 
             markersize=8, label='Testing Accuracy', markeredgecolor='black', markeredgewidth=2)
    
    ax1.fill_between(sizes_plot, train_scores, alpha=0.2, color='#2ecc71')
    ax1.fill_between(sizes_plot, test_scores, alpha=0.2, color='#e74c3c')
    
    ax1.set_xlabel('Training Set Size', fontsize=14, fontweight='bold')
    ax1.set_ylabel('Accuracy (%)', fontsize=14, fontweight='bold')
    ax1.set_title('Learning Curve - Accuracy vs Dataset Size', fontsize=16, fontweight='bold')
    ax1.legend(fontsize=12, loc='lower right')
    ax1.grid(True, alpha=0.3)
    ax1.set_ylim([85, 105])
    
    # Add final accuracy annotations
    final_train = train_scores[-1]
    final_test = test_scores[-1]
    ax1.annotate(f'Final Train: {final_train:.2f}%', 
                xy=(sizes_plot[-1], final_train), 
                xytext=(-80, 20), textcoords='offset points',
                fontsize=11, fontweight='bold',
                bbox=dict(boxstyle='round', facecolor='#2ecc71', alpha=0.7),
                arrowprops=dict(arrowstyle='->', color='black', lw=2))
    
    ax1.annotate(f'Final Test: {final_test:.2f}%', 
                xy=(sizes_plot[-1], final_test), 
                xytext=(-80, -30), textcoords='offset points',
                fontsize=11, fontweight='bold',
                bbox=dict(boxstyle='round', facecolor='#e74c3c', alpha=0.7),
                arrowprops=dict(arrowstyle='->', color='black', lw=2))
    
    # Plot 2: Train vs Test Accuracy Bar Chart
    metrics_names = ['Training\nAccuracy', 'Testing\nAccuracy', 'Gap']
    metrics_values = [final_train, final_test, abs(final_train - final_test)]
    colors = ['#2ecc71', '#e74c3c', '#f39c12' if metrics_values[2] < 5 else '#c0392b']
    
    bars = ax2.bar(metrics_names, metrics_values, color=colors, 
                   edgecolor='black', linewidth=2, width=0.6)
    
    # Add value labels
    for bar, val in zip(bars, metrics_values):
        height = bar.get_height()
        ax2.text(bar.get_x() + bar.get_width()/2., height,
                f'{val:.2f}%', ha='center', va='bottom', 
                fontsize=14, fontweight='bold')
    
    ax2.set_ylabel('Accuracy / Gap (%)', fontsize=14, fontweight='bold')
    ax2.set_title('Final Model Performance', fontsize=16, fontweight='bold')
    ax2.grid(True, alpha=0.3, axis='y')
    ax2.set_ylim([0, 105])
    
    # Add threshold line for overfitting
    ax2.axhline(y=5, color='red', linestyle='--', linewidth=2, 
               label='Overfitting Threshold (5%)', alpha=0.7)
    ax2.legend(fontsize=11)
    
    # Add status indicator
    if metrics_values[2] < 2:
        status = "✓ Excellent - No Overfitting"
        status_color = '#2ecc71'
    elif metrics_values[2] < 5:
        status = "⚠ Good - Minor Overfitting"
        status_color = '#f39c12'
    else:
        status = "✗ Poor - Significant Overfitting"
        status_color = '#c0392b'
    
    ax2.text(0.5, 0.95, status, transform=ax2.transAxes,
            fontsize=13, fontweight='bold', ha='center', va='top',
            bbox=dict(boxstyle='round', facecolor=status_color, alpha=0.3))
    
    plt.suptitle(f'{model_name} - Accuracy Analysis', fontsize=18, fontweight='bold', y=0.98)
    plt.tight_layout()
    plt.savefig(save_path, dpi=300, bbox_inches='tight')
    plt.close()
    
    print_status(f"Accuracy curves saved: {save_path}", "success")


def plot_model_comparison(forensic_metrics, realtime_metrics, save_path):
    """Compare both models side by side"""
    fig, axes = plt.subplots(2, 2, figsize=(16, 12))
    
    # Plot 1: Accuracy comparison
    models = ['Forensic\n(57 features)', 'Real-Time\n(17 features)']
    test_accs = [forensic_metrics['test_acc'] * 100, realtime_metrics['test_acc'] * 100]
    train_accs = [forensic_metrics['train_acc'] * 100, realtime_metrics['train_acc'] * 100]
    
    x = np.arange(len(models))
    width = 0.35
    
    bars1 = axes[0, 0].bar(x - width/2, train_accs, width, label='Training', 
                          color='#3498db', edgecolor='black', linewidth=2)
    bars2 = axes[0, 0].bar(x + width/2, test_accs, width, label='Testing', 
                          color='#e74c3c', edgecolor='black', linewidth=2)
    
    axes[0, 0].set_ylabel('Accuracy (%)', fontsize=12, fontweight='bold')
    axes[0, 0].set_title('Accuracy Comparison', fontsize=14, fontweight='bold')
    axes[0, 0].set_xticks(x)
    axes[0, 0].set_xticklabels(models)
    axes[0, 0].legend(fontsize=11)
    axes[0, 0].grid(True, alpha=0.3, axis='y')
    axes[0, 0].set_ylim([0, 105])
    
    # Add value labels
    for bars in [bars1, bars2]:
        for bar in bars:
            height = bar.get_height()
            axes[0, 0].text(bar.get_x() + bar.get_width()/2., height,
                          f'{height:.1f}%', ha='center', va='bottom', fontsize=10, fontweight='bold')
    
    # Plot 2: Feature count and speed
    features = [forensic_metrics['n_features'], realtime_metrics['n_features']]
    times = [forensic_metrics['train_time'], realtime_metrics['train_time']]
    
    ax2 = axes[0, 1]
    ax2_twin = ax2.twinx()
    
    bars3 = ax2.bar(x - width/2, features, width, label='Features', 
                   color='#2ecc71', edgecolor='black', linewidth=2)
    bars4 = ax2_twin.bar(x + width/2, times, width, label='Training Time (s)', 
                        color='#f39c12', edgecolor='black', linewidth=2)
    
    ax2.set_ylabel('Number of Features', fontsize=12, fontweight='bold', color='#2ecc71')
    ax2_twin.set_ylabel('Training Time (seconds)', fontsize=12, fontweight='bold', color='#f39c12')
    ax2.set_title('Features & Training Time', fontsize=14, fontweight='bold')
    ax2.set_xticks(x)
    ax2.set_xticklabels(models)
    ax2.tick_params(axis='y', labelcolor='#2ecc71')
    ax2_twin.tick_params(axis='y', labelcolor='#f39c12')
    
    # Add legends
    lines1, labels1 = ax2.get_legend_handles_labels()
    lines2, labels2 = ax2_twin.get_legend_handles_labels()
    ax2.legend(lines1 + lines2, labels1 + labels2, loc='upper left', fontsize=10)
    
    # Plot 3: Error rates
    fpr_forensic = forensic_metrics.get('fpr', 0) * 100
    fnr_forensic = forensic_metrics.get('fnr', 0) * 100
    fpr_realtime = realtime_metrics.get('fpr', 0) * 100
    fnr_realtime = realtime_metrics.get('fnr', 0) * 100
    
    error_types = ['False Positive\nRate', 'False Negative\nRate']
    forensic_errors = [fpr_forensic, fnr_forensic]
    realtime_errors = [fpr_realtime, fnr_realtime]
    
    x_err = np.arange(len(error_types))
    
    bars5 = axes[1, 0].bar(x_err - width/2, forensic_errors, width, label='Forensic', 
                          color='#9b59b6', edgecolor='black', linewidth=2)
    bars6 = axes[1, 0].bar(x_err + width/2, realtime_errors, width, label='Real-Time', 
                          color='#e67e22', edgecolor='black', linewidth=2)
    
    axes[1, 0].set_ylabel('Error Rate (%)', fontsize=12, fontweight='bold')
    axes[1, 0].set_title('Error Rates Comparison', fontsize=14, fontweight='bold')
    axes[1, 0].set_xticks(x_err)
    axes[1, 0].set_xticklabels(error_types)
    axes[1, 0].legend(fontsize=11)
    axes[1, 0].grid(True, alpha=0.3, axis='y')
    
    # Add value labels
    for bars in [bars5, bars6]:
        for bar in bars:
            height = bar.get_height()
            axes[1, 0].text(bar.get_x() + bar.get_width()/2., height,
                          f'{height:.2f}%', ha='center', va='bottom', fontsize=9, fontweight='bold')
    
    # Plot 4: Performance summary table
    axes[1, 1].axis('off')
    
    summary_data = [
        ['Metric', 'Forensic', 'Real-Time', 'Difference'],
        ['Test Accuracy', f"{forensic_metrics['test_acc']*100:.2f}%", 
         f"{realtime_metrics['test_acc']*100:.2f}%",
         f"{(forensic_metrics['test_acc']-realtime_metrics['test_acc'])*100:+.2f}%"],
        ['Features', str(forensic_metrics['n_features']), 
         str(realtime_metrics['n_features']),
         f"-{forensic_metrics['n_features']-realtime_metrics['n_features']}"],
        ['Training Time', f"{forensic_metrics['train_time']:.1f}s", 
         f"{realtime_metrics['train_time']:.1f}s",
         f"{forensic_metrics['train_time']/realtime_metrics['train_time']:.1f}x slower"],
        ['FPR', f"{fpr_forensic:.2f}%", f"{fpr_realtime:.2f}%", 
         f"{fpr_realtime-fpr_forensic:+.2f}%"],
        ['FNR', f"{fnr_forensic:.2f}%", f"{fnr_realtime:.2f}%", 
         f"{fnr_realtime-fnr_forensic:+.2f}%"]
    ]
    
    table = axes[1, 1].table(cellText=summary_data, cellLoc='center', loc='center',
                            colWidths=[0.3, 0.23, 0.23, 0.24])
    
    table.auto_set_font_size(False)
    table.set_fontsize(10)
    table.scale(1, 2.5)
    
    # Style header row
    for i in range(4):
        table[(0, i)].set_facecolor('#3498db')
        table[(0, i)].set_text_props(weight='bold', color='white')
    
    # Alternate row colors
    for i in range(1, len(summary_data)):
        color = '#ecf0f1' if i % 2 == 0 else 'white'
        for j in range(4):
            table[(i, j)].set_facecolor(color)
    
    axes[1, 1].set_title('Performance Summary', fontsize=14, fontweight='bold', pad=20)
    
    plt.suptitle('Model Comparison Dashboard', fontsize=18, fontweight='bold', y=0.98)
    plt.tight_layout()
    plt.savefig(save_path, dpi=300, bbox_inches='tight')
    plt.close()
    
    print_status(f"Model comparison dashboard saved: {save_path}", "success")


def validate_dataset(data):
    print_status("Validating dataset...", "info")
    
    # Check minimum size
    if len(data) < 100:
        return False, "Dataset too small (minimum 100 samples required)"
    
    # Check for required column types
    if 'Class' not in data.columns and 'Category' not in data.columns:
        return False, "No 'Class' or 'Category' column found"
    
    # Check for sufficient features
    feature_cols = [col for col in data.columns if col not in ['Class', 'Category']]
    if len(feature_cols) < 10:
        return False, f"Insufficient features ({len(feature_cols)} found, minimum 10 required)"
    
    # Check for extreme imbalance
    if 'Class' in data.columns:
        class_dist = data['Class'].value_counts()
    elif 'Category' in data.columns:
        class_dist = data['Category'].value_counts()
    
    if len(class_dist) < 2:
        return False, "Dataset must have at least 2 classes"
    
    imbalance_ratio = class_dist.max() / class_dist.min()
    if imbalance_ratio > 100:
        return False, f"Extreme class imbalance (ratio: {imbalance_ratio:.1f}:1)"
    
    print_status(f"  ✓ Dataset structure valid", "success")
    print_status(f"  ✓ {len(data):,} samples", "success")
    print_status(f"  ✓ {len(feature_cols)} features", "success")
    print_status(f"  ✓ Class balance ratio: {imbalance_ratio:.2f}:1", "success")
    
    return True, None


def preprocess_data(data):
    print_status("Preprocessing data...", "info")
    
    # Handle Class column
    if 'Class' not in data.columns:
        if 'Category' in data.columns:
            print_status("Converting Category to binary Class", "info")
            data['Class'] = data['Category'].apply(
                lambda x: 0 if str(x).strip().lower() in ['benign', '0', 'clean'] else 1
            )
        else:
            raise ValueError("No Class or Category column found")
    
    # Ensure Class is numeric
    if data['Class'].dtype == 'object':
        print_status("Converting Class to numeric format", "info")
        data['Class'] = data['Class'].apply(
            lambda x: 0 if str(x).strip().lower() in ['benign', '0', 'clean'] else 1
        )
    
    # Handle missing values
    missing_count = data.isnull().sum().sum()
    if missing_count > 0:
        print_status(f"Filling {missing_count:,} missing values with 0", "warning")
        data = data.fillna(0)
    
    # Handle infinite values
    data = data.replace([np.inf, -np.inf], 0)
    
    # Separate features and labels
    exclude_cols = ['Class', 'Category']
    feature_cols = [col for col in data.columns if col not in exclude_cols]
    
    X_full = data[feature_cols]
    y = data['Class']
    
    # Verify labels
    unique_labels = y.unique()
    if len(unique_labels) != 2:
        raise ValueError(f"Expected 2 classes, found {len(unique_labels)}: {unique_labels}")
    
    if not set(unique_labels).issubset({0, 1}):
        raise ValueError(f"Labels must be 0 and 1, found: {unique_labels}")
    
    # Print statistics
    print_status(f"Features: {len(feature_cols)}", "success")
    print_status(f"Benign samples: {(y==0).sum():,} ({(y==0).sum()/len(y)*100:.1f}%)", "info")
    print_status(f"Malicious samples: {(y==1).sum():,} ({(y==1).sum()/len(y)*100:.1f}%)", "info")
    
    return X_full, y, feature_cols


def train_dual_models(dataset_file):
    
    print_section("DUAL MODEL TRAINING SYSTEM v3.0 - WITH VISUALIZATIONS")
    print_status("Training models with comprehensive plots and metrics", "info")
    
    # Create visualizations directory
    os.makedirs('visualizations', exist_ok=True)
    
    # --- 1. Load Dataset ---
    print_status("Loading CIC-MalMem-2022 dataset...", "info")
    
    if not os.path.exists(dataset_file):
        print_status("ERROR: Dataset file not found!", "error")
        print(f"Looking for: {os.path.abspath(dataset_file)}")
        sys.exit(1)
    
    try:
        data = pd.read_csv(dataset_file)
        print_status(f"Dataset loaded: {len(data):,} samples", "success")
    except Exception as e:
        print_status(f"Error loading dataset: {e}", "error")
        sys.exit(1)
    
    # --- 2. Validate Dataset ---
    is_valid, error_msg = validate_dataset(data)
    if not is_valid:
        print_status(f"Dataset validation failed: {error_msg}", "error")
        sys.exit(1)
    
    # --- 3. Preprocess Data ---
    try:
        X_full, y, feature_cols = preprocess_data(data)
    except Exception as e:
        print_status(f"Preprocessing failed: {e}", "error")
        sys.exit(1)
    
    # --- 4. Create Real-Time Features ---
    print_status("Creating real-time feature mapping...", "info")
    
    mapper = FeatureMapper()
    X_realtime = mapper.map_volatility_to_realtime(X_full)
    X_realtime_df = pd.DataFrame(X_realtime, columns=mapper.REALTIME_FEATURES)
    
    # --- 5. Split Data ---
    print_status("Splitting data (80/20 train/test)...", "info")
    
    X_full_train, X_full_test, y_train, y_test = train_test_split(
        X_full, y, test_size=0.2, random_state=42, stratify=y
    )
    
    X_rt_train, X_rt_test = train_test_split(
        X_realtime_df, test_size=0.2, random_state=42, stratify=y
    )
    
    # --- 6. Train Forensic Model ---
    print_section("TRAINING FORENSIC MODEL (57 features)")
    
    clf_forensic = RandomForestClassifier(
        n_estimators=100, max_depth=20, min_samples_split=5,
        min_samples_leaf=2, random_state=42, n_jobs=-1, verbose=0
    )
    
    print_status("Training forensic model...", "info")
    start_time = datetime.now()
    clf_forensic.fit(X_full_train, y_train)
    forensic_time = (datetime.now() - start_time).total_seconds()
    
    # Evaluate
    y_forensic_train_pred = clf_forensic.predict(X_full_train)
    y_forensic_test_pred = clf_forensic.predict(X_full_test)
    y_forensic_proba = clf_forensic.predict_proba(X_full_test)[:, 1]
    
    forensic_train_acc = accuracy_score(y_train, y_forensic_train_pred)
    forensic_test_acc = accuracy_score(y_test, y_forensic_test_pred)
    
    cv_scores_forensic = cross_val_score(clf_forensic, X_full_train, y_train, cv=5, n_jobs=-1)
    
    cm_forensic = confusion_matrix(y_test, y_forensic_test_pred)
    tn_f, fp_f, fn_f, tp_f = cm_forensic.ravel()
    fpr_forensic = fp_f / (fp_f + tn_f)
    fnr_forensic = fn_f / (fn_f + tp_f)
    
    print_status(f"Testing accuracy: {forensic_test_acc*100:.2f}%", "success")
    
    # --- 7. Train Real-Time Model ---
    print_section("TRAINING REAL-TIME MODEL (17 features)")
    
    clf_realtime = RandomForestClassifier(
        n_estimators=50, max_depth=15, min_samples_split=5,
        min_samples_leaf=2, random_state=42, n_jobs=1, verbose=0
    )
    
    print_status("Training real-time model...", "info")
    start_time = datetime.now()
    clf_realtime.fit(X_rt_train, y_train)
    realtime_time = (datetime.now() - start_time).total_seconds()
    
    # Evaluate
    y_realtime_train_pred = clf_realtime.predict(X_rt_train)
    y_realtime_test_pred = clf_realtime.predict(X_rt_test)
    y_realtime_proba = clf_realtime.predict_proba(X_rt_test)[:, 1]
    
    realtime_train_acc = accuracy_score(y_train, y_realtime_train_pred)
    realtime_test_acc = accuracy_score(y_test, y_realtime_test_pred)
    
    cv_scores_realtime = cross_val_score(clf_realtime, X_rt_train, y_train, cv=5, n_jobs=-1)
    
    cm_realtime = confusion_matrix(y_test, y_realtime_test_pred)
    tn_r, fp_r, fn_r, tp_r = cm_realtime.ravel()
    fpr_realtime = fp_r / (fp_r + tn_r)
    fnr_realtime = fn_r / (fn_r + tp_r)
    
    print_status(f"Testing accuracy: {realtime_test_acc*100:.2f}%", "success")
    
    # --- 8. GENERATE ALL VISUALIZATIONS ---
    print_section("GENERATING VISUALIZATIONS")
    
    # Accuracy evolution curves
    plot_accuracy_curves(clf_forensic, X_full_train, X_full_test, y_train, y_test,
                        "Forensic Model", "visualizations/accuracy_curves_forensic.png")
    plot_accuracy_curves(clf_realtime, X_rt_train, X_rt_test, y_train, y_test,
                        "Real-Time Model", "visualizations/accuracy_curves_realtime.png")
    
    # Confusion matrices
    plot_confusion_matrix(cm_forensic, "Forensic Model", 
                         "visualizations/confusion_matrix_forensic.png")
    plot_confusion_matrix(cm_realtime, "Real-Time Model", 
                         "visualizations/confusion_matrix_realtime.png")
    
    # ROC curves
    plot_roc_curve(y_test, y_forensic_proba, "Forensic Model",
                  "visualizations/roc_curve_forensic.png")
    plot_roc_curve(y_test, y_realtime_proba, "Real-Time Model",
                  "visualizations/roc_curve_realtime.png")
    
    # Precision-Recall curves
    plot_precision_recall_curve(y_test, y_forensic_proba, "Forensic Model",
                               "visualizations/pr_curve_forensic.png")
    plot_precision_recall_curve(y_test, y_realtime_proba, "Real-Time Model",
                               "visualizations/pr_curve_realtime.png")
    
    # Feature importance
    plot_feature_importance(feature_cols, clf_forensic.feature_importances_,
                           "Forensic Model", "visualizations/feature_importance_forensic.png")
    plot_feature_importance(mapper.REALTIME_FEATURES, clf_realtime.feature_importances_,
                           "Real-Time Model", "visualizations/feature_importance_realtime.png", top_n=17)
    
    # Training metrics
    plot_training_metrics(forensic_train_acc, forensic_test_acc, cv_scores_forensic,
                         "Forensic Model", "visualizations/training_metrics_forensic.png")
    plot_training_metrics(realtime_train_acc, realtime_test_acc, cv_scores_realtime,
                         "Real-Time Model", "visualizations/training_metrics_realtime.png")
    
    # Model comparison dashboard
    forensic_metrics = {
        'train_acc': forensic_train_acc,
        'test_acc': forensic_test_acc,
        'n_features': len(feature_cols),
        'train_time': forensic_time,
        'fpr': fpr_forensic,
        'fnr': fnr_forensic
    }
    
    realtime_metrics = {
        'train_acc': realtime_train_acc,
        'test_acc': realtime_test_acc,
        'n_features': len(mapper.REALTIME_FEATURES),
        'train_time': realtime_time,
        'fpr': fpr_realtime,
        'fnr': fnr_realtime
    }
    
    plot_model_comparison(forensic_metrics, realtime_metrics,
                         "visualizations/model_comparison_dashboard.png")
    
    print_status("All visualizations generated successfully!", "success")
    
    # --- 9. Print Reports ---
    print_section("REAL-TIME MODEL EVALUATION")
    
    print("\nClassification Report:")
    print(classification_report(y_test, y_realtime_test_pred, 
                                target_names=['Benign', 'Malicious'], digits=4))
    
    # --- 10. Save Models ---
    print_section("SAVING MODELS")
    
    os.makedirs('models', exist_ok=True)
    
    # Save forensic model
    with open('models/fileless_malware_model_forensic.pkl', 'wb') as f:
        pickle.dump(clf_forensic, f)
    
    with open('models/forensic_features.pkl', 'wb') as f:
        pickle.dump(feature_cols, f)
    
    # Save real-time model
    with open('models/fileless_malware_model_realtime.pkl', 'wb') as f:
        pickle.dump(clf_realtime, f)
    
    with open('models/realtime_features.pkl', 'wb') as f:
        pickle.dump(mapper.REALTIME_FEATURES, f)
    
    with open('models/feature_mapper.pkl', 'wb') as f:
        pickle.dump(mapper, f)
    
    # Save metadata
    metadata = {
        'training_date': datetime.now().isoformat(),
        'forensic_model': {
            'test_accuracy': float(forensic_test_acc),
            'cv_accuracy_mean': float(cv_scores_forensic.mean()),
            'fpr': float(fpr_forensic),
            'fnr': float(fnr_forensic)
        },
        'realtime_model': {
            'test_accuracy': float(realtime_test_acc),
            'cv_accuracy_mean': float(cv_scores_realtime.mean()),
            'fpr': float(fpr_realtime),
            'fnr': float(fnr_realtime)
        }
    }
    
    with open('models/model_metadata.json', 'w') as f:
        json.dump(metadata, f, indent=2)
    
    print_status("All models and metadata saved!", "success")
    
    # --- 11. Summary ---
    print_section("TRAINING COMPLETE ✅")
    
    print(f"""
{Colors.SUCCESS}Successfully trained and visualized DUAL models!{Colors.RESET}

{Colors.INFO}REAL-TIME MODEL:{Colors.RESET}
  Test Accuracy: {realtime_test_acc*100:.2f}%
  CV Accuracy: {cv_scores_realtime.mean()*100:.2f}% (±{cv_scores_realtime.std()*100:.2f}%)
  False Positive Rate: {fpr_realtime*100:.2f}%
  
{Colors.SUCCESS}VISUALIZATIONS SAVED:{Colors.RESET}
  📈 Accuracy learning curves (NEW!)
  📊 Confusion matrices
  📈 ROC curves
  📉 Precision-Recall curves
  🔍 Feature importance plots
  📊 Training metrics comparison
  📊 Model comparison dashboard
  
{Colors.INFO}Location: ./visualizations/{Colors.RESET}

{Colors.SUCCESS}Ready for deployment! 🚀{Colors.RESET}
""")


def main():
    print(f"""
{Colors.INFO}╔═══════════════════════════════════════════════════════╗
║                                                       ║
║     DataDefenceX ML Training System v3.0             ║
║     With Complete Visualizations                     ║
║                                                       ║
╚═══════════════════════════════════════════════════════╝{Colors.RESET}
    """)
    
    dataset_file = "Obfuscated-MalMem2022.csv"
    
    if len(sys.argv) > 1:
        dataset_file = sys.argv[1]
    
    try:
        train_dual_models(dataset_file)
    except KeyboardInterrupt:
        print(f"\n\n{Colors.WARNING}Training interrupted.{Colors.RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n{Colors.ERROR}Error: {e}{Colors.RESET}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()