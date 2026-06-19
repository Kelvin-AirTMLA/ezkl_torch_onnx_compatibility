"""
Proof-of-Scan — landmark embedding MLP training and ONNX export.

Input:  (1, 128) normalized facial landmark embedding (private witness)
Output: (1, 2)  logits for 0=Not Verified, 1=Verified Human
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ONNX_PATH = PROJECT_ROOT / "02_model_export" / "identity_vault.onnx"
METRICS_PATH = PROJECT_ROOT / "02_model_export" / "training_metrics.json"

INPUT_DIM = 128
HIDDEN_DIM = 32
OUTPUT_DIM = 2
BATCH_SIZE = 32
EPOCHS = 80
LEARNING_RATE = 0.005
OPSET_VERSION = 15


class IdentityVaultMLP(nn.Module):
    """3-layer MLP for offline landmark embedding classification."""

    def __init__(self) -> None:
        super().__init__()
        self.fc1 = nn.Linear(INPUT_DIM, HIDDEN_DIM, dtype=torch.float32)
        self.fc2 = nn.Linear(HIDDEN_DIM, HIDDEN_DIM, dtype=torch.float32)
        self.fc3 = nn.Linear(HIDDEN_DIM, OUTPUT_DIM, dtype=torch.float32)
        self.relu = nn.ReLU()

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = self.relu(self.fc1(x))
        x = self.relu(self.fc2(x))
        return self.fc3(x)


def synthesize_embedding_dataset(n_samples: int, rng: np.random.Generator) -> tuple[torch.Tensor, torch.Tensor]:
    """Synthetic enrolled vs impostor landmark embeddings."""
    enrolled_center = rng.normal(0.0, 0.2, size=(INPUT_DIM,)).astype(np.float32)
    impostor_center = rng.normal(0.5, 0.3, size=(INPUT_DIM,)).astype(np.float32)

    features = np.zeros((n_samples, INPUT_DIM), dtype=np.float32)
    labels = np.zeros(n_samples, dtype=np.int64)
    for i in range(n_samples):
        is_enrolled = rng.random() > 0.5
        center = enrolled_center if is_enrolled else impostor_center
        features[i] = center + rng.normal(0.0, 0.08, size=(INPUT_DIM,)).astype(np.float32)
        labels[i] = 1 if is_enrolled else 0

    x = torch.from_numpy(features).to(dtype=torch.float32)
    y = torch.from_numpy(labels).to(dtype=torch.long)
    return x, y


def train_model(model: IdentityVaultMLP, x: torch.Tensor, y: torch.Tensor) -> float:
    criterion = nn.CrossEntropyLoss()
    optimizer = optim.Adam(model.parameters(), lr=LEARNING_RATE)
    model.train()
    final_loss = 0.0
    n = x.shape[0]
    for _ in range(EPOCHS):
        perm = torch.randperm(n)
        epoch_loss = 0.0
        batches = 0
        for start in range(0, n, BATCH_SIZE):
            idx = perm[start : start + BATCH_SIZE]
            batch_x = x[idx]
            batch_y = y[idx]
            optimizer.zero_grad()
            logits = model(batch_x)
            loss = criterion(logits, batch_y)
            loss.backward()
            optimizer.step()
            epoch_loss += loss.item()
            batches += 1
        final_loss = epoch_loss / max(batches, 1)
    return final_loss


def export_onnx(model: IdentityVaultMLP, output_path: Path) -> None:
    model.eval()
    dummy = torch.zeros((1, INPUT_DIM), dtype=torch.float32)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    torch.onnx.export(
        model,
        dummy,
        str(output_path),
        export_params=True,
        opset_version=OPSET_VERSION,
        do_constant_folding=True,
        input_names=["landmark_embedding"],
        output_names=["verification_logits"],
        dynamic_axes=None,
    )


def main() -> None:
    rng = np.random.default_rng(17)
    x, y = synthesize_embedding_dataset(n_samples=512, rng=rng)

    model = IdentityVaultMLP()
    final_loss = train_model(model, x, y)
    export_onnx(model, ONNX_PATH)

    metrics = {
        "model_training_loss": final_loss,
        "onnx_path": str(ONNX_PATH),
        "onnx_size_kb": round(ONNX_PATH.stat().st_size / 1024, 3),
        "input_shape": [1, INPUT_DIM],
        "output_shape": [1, OUTPUT_DIM],
        "opset_version": OPSET_VERSION,
    }
    METRICS_PATH.write_text(json.dumps(metrics, indent=2))
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
