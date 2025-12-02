"""
Vulnerability Detection GNN Model Definition

This module defines the Graph Neural Network (GNN) architecture used for
classifying Python code as vulnerable or safe. The model uses a combination
of Graph Convolutional Network (GCN) layers and Graph Attention (GAT) layers
to learn representations from the code's Abstract Syntax Tree (AST).

Enhanced with:
- Residual connections for better gradient flow
- Batch normalization for training stability
- Multi-pooling (mean + max + sum) for richer graph representations
- Dual GAT layers for improved attention
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GATConv, GCNConv, global_max_pool, global_mean_pool, global_add_pool


class VulnerabilityGNN(nn.Module):
    """
    Enhanced GNN for Code Vulnerability Detection.

    This model processes graph representations of source code (ASTs) to
    predict whether the code contains a vulnerability.

    Args:
        num_node_features (int): The dimensionality of the input node features.
        hidden_channels (int): The number of channels in the hidden layers.
        num_classes (int): The number of output classes (2 = vulnerable/safe).
        dropout (float): The dropout rate for regularization.
        gcn_layers (int): The number of GCN layers to apply.
        gat_heads (int): The number of attention heads in the GAT layer.
        use_batch_norm (bool): Whether to use batch normalization.
        use_residual (bool): Whether to use residual connections.
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

        # Initial projection layer (maps node features to hidden dimension)
        self.input_proj = nn.Linear(num_node_features, hidden_channels)
        
        # GCN layers
        self.gcn_layers = nn.ModuleList()
        self.batch_norms = nn.ModuleList() if use_batch_norm else None
        
        for _ in range(gcn_layers):
            self.gcn_layers.append(GCNConv(hidden_channels, hidden_channels))
            if use_batch_norm:
                self.batch_norms.append(nn.BatchNorm1d(hidden_channels))

        # Graph Attention Layer
        self.gat = GATConv(
            hidden_channels, hidden_channels, 
            heads=gat_heads, 
            concat=False, 
            dropout=dropout
        )
        self.gat_norm = nn.BatchNorm1d(hidden_channels) if use_batch_norm else None

        # Classification Head (MLP)
        # Using 2x hidden_channels because we concatenate mean and max pooling
        self.classifier = nn.Sequential(
            nn.Linear(hidden_channels * 2, hidden_channels),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_channels, hidden_channels // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_channels // 2, num_classes)
        )

    def forward(
        self, x: torch.Tensor, edge_index: torch.Tensor, batch: torch.Tensor
    ) -> torch.Tensor:
        """
        Forward pass of the model.

        Args:
            x: Node feature matrix [num_nodes, num_node_features]
            edge_index: Graph connectivity [2, num_edges]
            batch: Batch vector assigning nodes to graphs [num_nodes]

        Returns:
            Output logits [batch_size, num_classes]
        """
        # Initial projection to hidden dimension
        x = self.input_proj(x)
        x = F.relu(x)
        
        # GCN layers with optional residual connections and batch norm
        for i, conv in enumerate(self.gcn_layers):
            identity = x if self.use_residual else None
            
            x = conv(x, edge_index)
            
            if self.use_batch_norm:
                x = self.batch_norms[i](x)
            
            x = F.relu(x)
            x = F.dropout(x, p=self.dropout, training=self.training)
            
            if self.use_residual:
                x = x + identity

        # GAT layer with residual
        identity = x if self.use_residual else None
        x = self.gat(x, edge_index)
        
        if self.use_batch_norm and self.gat_norm is not None:
            x = self.gat_norm(x)
        
        x = F.elu(x)
        
        if self.use_residual:
            x = x + identity

        # Global pooling (aggregate node features to graph-level)
        x_mean = global_mean_pool(x, batch)
        x_max = global_max_pool(x, batch)
        x = torch.cat([x_mean, x_max], dim=1)

        # Classification
        x = self.classifier(x)

        return x
