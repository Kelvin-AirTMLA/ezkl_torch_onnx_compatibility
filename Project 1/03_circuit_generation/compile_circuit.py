"""
Proof-of-Scan — EZKL settings generation and scale calibration.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import ezkl
import numpy as np
import torch
import torch.nn as nn

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ONNX_PATH = PROJECT_ROOT / "02_model_export" / "identity_vault.onnx"
SETTINGS_PATH = PROJECT_ROOT / "03_circuit_generation" / "settings.json"
INPUT_JSON = PROJECT_ROOT / "03_circuit_generation" / "input.json"

INPUT_DIM = 128
OUTPUT_DIM = 2


class IdentityVaultMLP(nn.Module):
    def __init__(self) -> None:
        super().__init__()
        self.fc1 = nn.Linear(INPUT_DIM, 32, dtype=torch.float32)
        self.fc2 = nn.Linear(32, 32, dtype=torch.float32)
        self.fc3 = nn.Linear(32, OUTPUT_DIM, dtype=torch.float32)
        self.relu = nn.ReLU()

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = self.relu(self.fc1(x))
        x = self.relu(self.fc2(x))
        return self.fc3(x)


def refresh_input_json() -> None:
    rng = np.random.default_rng(0)
    sample = rng.normal(0.0, 0.15, size=(1, INPUT_DIM)).astype(np.float32)

    model = IdentityVaultMLP()
    model.eval()
    with torch.no_grad():
        output = model(torch.from_numpy(sample)).numpy()

    payload = {
        "input_data": [sample.reshape(-1).tolist()],
        "output_data": [output.reshape(-1).tolist()],
    }
    INPUT_JSON.write_text(json.dumps(payload, indent=2))


def main() -> None:
    if not ONNX_PATH.exists():
        raise FileNotFoundError(
            f"Missing {ONNX_PATH}. Run 02_model_export/train_and_export.py first."
        )

    refresh_input_json()
    SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)

    circuit_dir = SETTINGS_PATH.parent
    onnx_rel = os.path.relpath(ONNX_PATH, circuit_dir)
    input_rel = os.path.relpath(INPUT_JSON, circuit_dir)
    settings_name = SETTINGS_PATH.name

    prev_cwd = os.getcwd()
    os.chdir(circuit_dir)
    try:
        ezkl.gen_settings(onnx_rel)
        ezkl.calibrate_settings(
            data=input_rel,
            model=onnx_rel,
            settings=settings_name,
            target="resources",
        )
    finally:
        os.chdir(prev_cwd)

    summary = {
        "onnx": str(ONNX_PATH),
        "settings": str(SETTINGS_PATH),
        "input_json": str(INPUT_JSON),
    }
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
