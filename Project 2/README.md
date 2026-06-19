# Project 2: TrustAgent — Verifiable Credit Scorer

Automates decentralized credit-tier decisions with a zk-SNARK proof. Private financial inputs stay off-chain; the chain only verifies that a PyTorch MLP was executed correctly.

---

## Pipeline

```
01_environment_setup/   → pip install
02_model_export/        → train PyTorch MLP → credit_scorer.onnx
03_circuit_generation/  → gen_settings + calibrate → settings.json
04_proof_and_verify/    → compile → witness → prove → verify → EVM verifier
05_benchmarks/          → end-to-end timing report
```

---

## Model spec

| | |
|---|---|
| **Input** | `(1, 3)` — `[Normalized_Income, Total_Debt, Delinquency_Marker]` |
| **Output** | `(1, 3)` — logits for tier `0` High Risk, `1` Medium, `2` Prime |
| **Architecture** | 3-layer MLP (Linear → ReLU → Linear → ReLU → Linear) |
| **Export** | `torch.onnx.export`, opset 15, static batch |

---

## Quick start

```bash
cd "Project 2"
python -m venv .venv && source .venv/bin/activate
pip install -r 01_environment_setup/requirements.txt

python 02_model_export/train_and_export.py
python 03_circuit_generation/compile_circuit.py
python 04_proof_and_verify/generate_proof.py

# Full benchmark (training + ONNX + witness + prove metrics)
python 05_benchmarks/benchmark_runner.py
```

`prove` may take several minutes on CPU for this circuit size.

---

## Directory layout

```
Project 2/
├── 01_environment_setup/
│   └── requirements.txt
├── 02_model_export/
│   ├── train_and_export.py
│   └── credit_scorer.onnx          # generated
├── 03_circuit_generation/
│   ├── input.json                  # private financial witness payload
│   ├── compile_circuit.py
│   └── settings.json               # generated
├── 04_proof_and_verify/
│   ├── generate_proof.py
│   ├── witness.json                # generated
│   ├── network.proof               # generated
│   └── TrustAgentVerifier.sol      # generated (requires solc)
└── 05_benchmarks/
    ├── benchmark_runner.py
    └── benchmark_report.json
```

---

## Public vs private

| Private (witness) | Public (on-chain) |
|-------------------|-------------------|
| Income, debt, delinquency | Proof bytes |
| Raw financial decimals | Credit tier / policy ID (optional) |

---

## References

- [../README.md](../README.md) — common ezkl errors and fixes  
- [../reference-pipeline/](../reference-pipeline/) — Keras tutorial (this project uses PyTorch)  
- [EZKL docs](https://docs.ezkl.xyz/)
