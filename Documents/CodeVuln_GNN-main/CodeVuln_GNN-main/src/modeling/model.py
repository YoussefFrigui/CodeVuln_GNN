"""
Vulnerability Detection GNN Model Definition

This module defines the Graph Neural Network (GNN) architecture used for
classifying Python code as vulnerable or safe. The model uses a combination
of Graph Convolutional Network (GCN) layers and a Graph Attention (GAT) layer
to learn representations from the code's Abstract Syntax Tree (AST).
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GATConv, GCNConv, global_max_pool, global_mean_pool


class VulnerabilityGNN(nn.Module):
    """
    A GNN for Code Vulnerability Detection.

    This model processes graph representations of source code (ASTs) to
    predict whether the code contains a vulnerability.

    Args:
        num_node_features (int): The dimensionality of the input node features.
        hidden_channels (int): The number of channels in the hidden layers.
        num_classes (int): The number of output classes (typically 2 for
                           vulnerable/safe).
        dropout (float): The dropout rate for regularization.
        gcn_layers (int): The number of GCN layers to apply.
        gat_heads (int): The number of attention heads in the GAT layer.
    """

    def __init__(
        self,
        num_node_features: int,
        hidden_channels: int,
        num_classes: int,
        dropout: float,
        gcn_layers: int,
        gat_heads: int,
    ):
        super().__init__()

        self.gcn_layers = nn.ModuleList()
        # First GCN layer
        self.gcn_layers.append(GCNConv(num_node_features, hidden_channels))
        # Subsequent GCN layers
        for _ in range(gcn_layers - 1):
            self.gcn_layers.append(GCNConv(hidden_channels, hidden_channels))

        # Graph Attention Layer
        self.gat = GATConv(
            hidden_channels, hidden_channels, heads=gat_heads, concat=False
        )

        # Classification Head
        self.lin1 = nn.Linear(hidden_channels, hidden_channels // 2)
        self.lin2 = nn.Linear(hidden_channels // 2, num_classes)

        self.dropout = dropout

    def forward(
        self, x: torch.Tensor, edge_index: torch.Tensor, batch: torch.Tensor
    ) -> torch.Tensor:
        """
        Defines the forward pass of the model.

        Args:
            x (torch.Tensor): Node feature matrix of shape [num_nodes, num_node_features].
            edge_index (torch.Tensor): Graph connectivity in COO format with shape [2, num_edges].
            batch (torch.Tensor): Batch vector of shape [num_nodes], which assigns each
                                  node to its respective graph.

        Returns:
            torch.Tensor: The output logits for each graph in the batch, with shape
                          [batch_size, num_classes].
        """
        # GCN layers with ReLU and Dropout
        for conv in self.gcn_layers:
            x = conv(x, edge_index)
            x = F.relu(x)
            x = F.dropout(x, p=self.dropout, training=self.training)

        # GAT layer
        x = self.gat(x, edge_index)
        x = F.relu(x)

        # Global Pooling (aggregate node features to graph-level)
        x = global_mean_pool(x, batch) + global_max_pool(x, batch)

        # Classification MLP
        x = self.lin1(x)
        x = F.relu(x)
        x = F.dropout(x, p=self.dropout, training=self.training)
        x = self.lin2(x)

        return x
