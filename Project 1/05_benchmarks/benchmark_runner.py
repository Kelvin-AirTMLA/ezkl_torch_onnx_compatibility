"""
Proof-of-Scan — end-to-end pipeline benchmark runner.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import ezkl

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PYTHON = sys.executable
REPORT_PATH = PROJECT_ROOT / "05_benchmarks" / "benchmark_report.json"

TRAIN_SCRIPT = PROJECT_ROOT / "02_model_export" / "train_and_export.py"
COMPILE_SCRIPT = PROJECT_ROOT / "03_circuit_generation" / "compile_circuit.py"

ONNX_PATH = PROJECT_ROOT / "02_model_export" / "identity_vault.onnx"
METRICS_PATH = PROJECT_ROOT / "02_model_export" / "training_metrics.json"
SETTINGS_PATH = PROJECT_ROOT / "03_circuit_generation" / "settings.json"
INPUT_JSON = PROJECT_ROOT / "03_circuit_generation" / "input.json"
CIRCUIT_PATH = PROJECT_ROOT / "04_proof_and_verify" / "network.ezkl"
WITNESS_PATH = PROJECT_ROOT / "04_proof_and_verify" / "witness.json"
PROOF_PATH = PROJECT_ROOT / "04_proof_and_verify" / "network.proof"
PK_PATH = PROJECT_ROOT / "04_proof_and_verify" / "pk.key"
VK_PATH = PROJECT_ROOT / "04_proof_and_verify" / "vk.key"
SRS_PATH = PROJECT_ROOT / "04_proof_and_verify" / "kzg.srs"


def run_script(script: Path) -> None:
    subprocess.run([PYTHON, str(script)], check=True, cwd=str(PROJECT_ROOT))


def main() -> None:
    pipeline_start = time.perf_counter()

    run_script(TRAIN_SCRIPT)
    train_metrics = json.loads(METRICS_PATH.read_text())
    run_script(COMPILE_SCRIPT)

    if not SRS_PATH.exists():
        ezkl.get_srs(str(SETTINGS_PATH), srs_path=str(SRS_PATH))
    if not CIRCUIT_PATH.exists():
        ezkl.compile_circuit(str(ONNX_PATH), str(CIRCUIT_PATH), str(SETTINGS_PATH))
    if not PK_PATH.exists() or not VK_PATH.exists():
        ezkl.setup(str(CIRCUIT_PATH), str(VK_PATH), str(PK_PATH), str(SRS_PATH))

    witness_start = time.perf_counter()
    ezkl.gen_witness(data=str(INPUT_JSON), model=str(CIRCUIT_PATH), output=str(WITNESS_PATH))
    witness_ms = (time.perf_counter() - witness_start) * 1000.0

    prove_start = time.perf_counter()
    ezkl.prove(
        witness=str(WITNESS_PATH),
        model=str(CIRCUIT_PATH),
        pk_path=str(PK_PATH),
        proof_path=str(PROOF_PATH),
        srs_path=str(SRS_PATH),
    )
    prove_ms = (time.perf_counter() - prove_start) * 1000.0

    report = {
        "project": "Proof-of-Scan Biometric Identity Vault",
        "model_training_loss": train_metrics["model_training_loss"],
        "onnx_file_footprint_kb": round(ONNX_PATH.stat().st_size / 1024, 3),
        "witness_computation_latency_ms": round(witness_ms, 2),
        "proof_generation_latency_ms": round(prove_ms, 2),
        "proof_file_footprint_bytes": PROOF_PATH.stat().st_size if PROOF_PATH.exists() else 0,
        "total_pipeline_seconds": round(time.perf_counter() - pipeline_start, 2),
    }
    REPORT_PATH.write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
