"""
Vulnerability Detection GNN Model Definition 

This module defines an improved Graph Neural Network (GNN) architecture for
classifying Python code as vulnerable or safe. Key improvements over v1:

1. Semantic Feature Attention: Dedicated attention to dangerous function features
2. Multi-Scale Pooling: Captures both local and global vulnerability patterns
3. Context-Aware Classification: Separate processing for structural vs semantic features
4. Improved False Positive Handling: Better discrimination of complex safe code

Architecture:
- Semantic Feature Projection: Highlights vulnerability-relevant features
- GCN layers: Learn structural patterns in AST
- Dual GAT layers: Multi-head attention for pattern focusing
- Hierarchical Pooling: Mean + Max + Attention-weighted pooling
- Context MLP: Combines structural and semantic signals
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GATConv, GCNConv, global_max_pool, global_mean_pool, global_add_pool
from torch_geometric.nn import GraphNorm


class SemanticFeatureAttention(nn.Module):
    """
    Attention module that highlights vulnerability-relevant semantic features.
    
    The 16-dim feature vector contains:
    [0] AST type, [1] Name hash, [2] Is dangerous, [3] Danger category,
    [4] User input, [5] String concat, [6] SQL, [7] Deserialize,
    [8] File op, [9] Crypto, [10] Network, [11] Module hash,
    [12] Dangerous import, [13] Depth, [14] Has dangerous child, [15] Parent dangerous
    
    This module learns to attend more to security-relevant features (indices 2-12, 14-15).
    """
    
    def __init__(self, num_features: int, hidden_dim: int = 32):
        super().__init__()
        self.attention = nn.Sequential(
            nn.Linear(num_features, hidden_dim),
            nn.Tanh(),
            nn.Linear(hidden_dim, num_features),
            nn.Sigmoid()
        )
        
        # Initialize with bias toward security features
        # Features 2-12 and 14-15 are security-relevant
        self.security_feature_indices = [2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 15]
    
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Apply learned attention weights to features."""
        attention_weights = self.attention(x)
        return x * attention_weights


class AttentionPooling(nn.Module):
    """
    Attention-based graph pooling that learns which nodes are most important.
    
    This helps the model focus on security-critical nodes (like function calls
    with dangerous functions) rather than treating all nodes equally.
    """
    
    def __init__(self, hidden_channels: int):
        super().__init__()
        self.attention = nn.Sequential(
            nn.Linear(hidden_channels, hidden_channels // 2),
            nn.Tanh(),
            nn.Linear(hidden_channels // 2, 1)
        )
    
    def forward(self, x: torch.Tensor, batch: torch.Tensor) -> torch.Tensor:
        """
        Compute attention-weighted pooling.
        
        Args:
            x: Node features [num_nodes, hidden_channels]
            batch: Batch assignment [num_nodes]
            
        Returns:
            Graph-level features [batch_size, hidden_channels]
        """
        # Compute attention scores
        attention_scores = self.attention(x)  # [num_nodes, 1]
        
        # Normalize attention within each graph using softmax
        # We need to do this per-graph
        attention_weights = torch.zeros_like(attention_scores)
        
        for graph_idx in batch.unique():
            mask = batch == graph_idx
            scores = attention_scores[mask]
            weights = F.softmax(scores, dim=0)
            attention_weights[mask] = weights
        
        # Apply attention weights and sum
        weighted_x = x * attention_weights
        
        # Sum pooling of weighted features
        return global_add_pool(weighted_x, batch)


class VulnerabilityGNN(nn.Module):
    """
    Enhanced GNN for Code Vulnerability Detection - v2.

    Improvements for reducing false positives:
    1. Semantic feature attention - focuses on security-relevant features
    2. Multi-scale GAT - captures patterns at different granularities  
    3. Hierarchical pooling - mean + max + attention for richer representations
    4. Deeper classifier with skip connections

    Args:
        num_node_features (int): Input feature dimension (16 for semantic features)
        hidden_channels (int): Hidden layer dimension
        num_classes (int): Output classes (2 = safe/vulnerable)
        dropout (float): Dropout rate
        gcn_layers (int): Number of GCN layers
        gat_heads (int): Number of GAT attention heads
        use_batch_norm (bool): Use batch normalization
        use_residual (bool): Use residual/skip connections
    """

    def __init__(
        self,
        num_node_features: int,
        hidden_channels: int,
        num_classes: int,
        dropout: float,
        gcn_layers: int,
        gat_heads: int,
        use_batch_norm: bool = True,
        use_residual: bool = True,
    ):
        super().__init__()
        
        self.num_gcn_layers = gcn_layers
        self.use_batch_norm = use_batch_norm
        self.use_residual = use_residual
        self.dropout = dropout
        self.hidden_channels = hidden_channels

        # ========== Feature Processing ==========
        # Semantic feature attention (learns to focus on security features)
        self.semantic_attention = SemanticFeatureAttention(num_node_features)
        
        # Initial projection with skip connection from raw features
        self.input_proj = nn.Linear(num_node_features, hidden_channels)
        self.input_norm = GraphNorm(hidden_channels) if use_batch_norm else None
        
        # ========== Graph Convolution Layers ==========
        self.gcn_layers = nn.ModuleList()
        self.gcn_norms = nn.ModuleList() if use_batch_norm else None
        
        for _ in range(gcn_layers):
            self.gcn_layers.append(GCNConv(hidden_channels, hidden_channels))
            if use_batch_norm:
                self.gcn_norms.append(GraphNorm(hidden_channels))

        # ========== Multi-Scale Graph Attention ==========
        # First GAT: Local patterns (fewer heads, captures local vulnerabilities)
        self.gat_local = GATConv(
            hidden_channels, hidden_channels, 
            heads=max(2, gat_heads // 2), 
            concat=False, 
            dropout=dropout
        )
        self.gat_local_norm = GraphNorm(hidden_channels) if use_batch_norm else None
        
        # Second GAT: Global patterns (more heads, captures context)
        self.gat_global = GATConv(
            hidden_channels, hidden_channels, 
            heads=gat_heads, 
            concat=False, 
            dropout=dropout
        )
        self.gat_global_norm = GraphNorm(hidden_channels) if use_batch_norm else None

        # ========== Hierarchical Pooling ==========
        self.attention_pooling = AttentionPooling(hidden_channels)
        
        # ========== Classification Head ==========
        # 3x hidden_channels: mean + max + attention pooling
        pooled_dim = hidden_channels * 3
        
        self.classifier = nn.Sequential(
            # First layer with larger capacity
            nn.Linear(pooled_dim, hidden_channels * 2),
            nn.LayerNorm(hidden_channels * 2),
            nn.GELU(),  # GELU often works better than ReLU for classification
            nn.Dropout(dropout),
            
            # Second layer
            nn.Linear(hidden_channels * 2, hidden_channels),
            nn.LayerNorm(hidden_channels),
            nn.GELU(),
            nn.Dropout(dropout),
            
            # Third layer (narrowing)
            nn.Linear(hidden_channels, hidden_channels // 2),
            nn.LayerNorm(hidden_channels // 2),
            nn.GELU(),
            nn.Dropout(dropout * 0.5),  # Less dropout near output
            
            # Output layer
            nn.Linear(hidden_channels // 2, num_classes)
        )
        
        # ========== Confidence Calibration ==========
        # Temperature scaling for better calibrated confidence scores
        self.temperature = nn.Parameter(torch.ones(1))

    def forward(
        self, x: torch.Tensor, edge_index: torch.Tensor, batch: torch.Tensor
    ) -> torch.Tensor:
        """
        Forward pass with hierarchical processing.

        Args:
            x: Node features [num_nodes, num_node_features]
            edge_index: Edge connectivity [2, num_edges]
            batch: Batch assignment [num_nodes]

        Returns:
            Logits [batch_size, num_classes]
        """
        # ========== 1. Semantic Feature Attention ==========
        # Highlight security-relevant features before projection
        x = self.semantic_attention(x)
        
        # ========== 2. Initial Projection ==========
        x = self.input_proj(x)
        if self.input_norm is not None:
            x = self.input_norm(x, batch)
        x = F.gelu(x)
        x = F.dropout(x, p=self.dropout * 0.5, training=self.training)
        
        # ========== 3. GCN Layers (Structural Learning) ==========
        for i, conv in enumerate(self.gcn_layers):
            identity = x if self.use_residual else None
            
            x = conv(x, edge_index)
            
            if self.use_batch_norm and self.gcn_norms is not None:
                x = self.gcn_norms[i](x, batch)
            
            x = F.gelu(x)
            x = F.dropout(x, p=self.dropout, training=self.training)
            
            if self.use_residual:
                x = x + identity

        # ========== 4. Multi-Scale GAT (Attention Learning) ==========
        # Local attention (fine-grained patterns)
        identity = x if self.use_residual else None
        x_local = self.gat_local(x, edge_index)
        if self.gat_local_norm is not None:
            x_local = self.gat_local_norm(x_local, batch)
        x_local = F.elu(x_local)
        
        # Global attention (broader context)
        x_global = self.gat_global(x, edge_index)
        if self.gat_global_norm is not None:
            x_global = self.gat_global_norm(x_global, batch)
        x_global = F.elu(x_global)
        
        # Combine local and global with residual
        x = (x_local + x_global) / 2.0
        if self.use_residual:
            x = x + identity
        
        x = F.dropout(x, p=self.dropout, training=self.training)

        # ========== 5. Hierarchical Pooling ==========
        # Mean pooling - average behavior
        x_mean = global_mean_pool(x, batch)
        
        # Max pooling - most activated features (strong signals)
        x_max = global_max_pool(x, batch)
        
        # Attention pooling - learned importance
        x_attn = self.attention_pooling(x, batch)
        
        # Concatenate all pooling strategies
        x = torch.cat([x_mean, x_max, x_attn], dim=1)

        # ========== 6. Classification ==========
        logits = self.classifier(x)
        
        # Temperature scaling for calibration (only during inference)
        if not self.training:
            logits = logits / self.temperature

        return logits
    
    def get_attention_weights(
        self, x: torch.Tensor, edge_index: torch.Tensor, batch: torch.Tensor
    ) -> dict:
        """
        Get attention weights for interpretability.
        
        Returns attention weights from both GAT layers and the pooling layer
        for visualization and debugging false positives.
        """
        # Process through the network
        x = self.semantic_attention(x)
        x = self.input_proj(x)
        if self.input_norm is not None:
            x = self.input_norm(x, batch)
        x = F.gelu(x)
        
        for i, conv in enumerate(self.gcn_layers):
            identity = x if self.use_residual else None
            x = conv(x, edge_index)
            if self.use_batch_norm and self.gcn_norms is not None:
                x = self.gcn_norms[i](x, batch)
            x = F.gelu(x)
            if self.use_residual:
                x = x + identity
        
        # Get GAT attention (would need to modify GATConv to return attention)
        # For now, return pooling attention
        pooling_attention = self.attention_pooling.attention(x)
        
        return {
            'pooling_attention': pooling_attention,
            'node_features': x,
        }
