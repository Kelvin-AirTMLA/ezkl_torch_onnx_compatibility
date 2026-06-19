# Project 1: Proof-of-Scan Biometric Identity Vault

Proves **“this wallet belongs to a verified human”** without publishing raw biometrics on-chain. Landmarks/embeddings stay in the witness; the chain verifies the zk-SNARK only.

---

## Pipeline

```
01_environment_setup/   → pip install
02_model_export/        → train embedding MLP → identity_vault.onnx
03_circuit_generation/  → gen_settings + calibrate → settings.json
04_proof_and_verify/    → compile → witness → prove → verify → EVM verifier
05_benchmarks/          → end-to-end timing report
```

The current boilerplate uses a **128-dim synthetic landmark embedding** as a stand-in until MediaPipe (or similar) is wired into `02_model_export/`.

---

## Model spec

| | |
|---|---|
| **Input** | `(1, 128)` — normalized facial landmark embedding (private) |
| **Output** | `(1, 2)` — logits for `0` Not Verified, `1` Verified Human |
| **Architecture** | 3-layer MLP |
| **Export** | `torch.onnx.export`, opset 15, static batch |

---

## Quick start

```bash
cd "Project 1"
python -m venv .venv && source .venv/bin/activate
pip install -r 01_environment_setup/requirements.txt

python 02_model_export/train_and_export.py
python 03_circuit_generation/compile_circuit.py
python 04_proof_and_verify/generate_proof.py

python 05_benchmarks/benchmark_runner.py
```

---

## Directory layout

```
Project 1/
├── 01_environment_setup/
│   └── requirements.txt
├── 02_model_export/
│   ├── train_and_export.py
│   └── identity_vault.onnx         # generated
├── 03_circuit_generation/
│   ├── input.json
│   ├── compile_circuit.py
│   └── settings.json               # generated
├── 04_proof_and_verify/
│   ├── generate_proof.py
│   ├── witness.json                # generated
│   ├── network.proof               # generated
│   └── IdentityVaultVerifier.sol   # generated (requires solc)
└── 05_benchmarks/
    ├── benchmark_runner.py
    └── benchmark_report.json
```

---

## Public vs private

| Private (witness) | Public (on-chain) |
|-------------------|-------------------|
| Landmark embedding | Proof bytes |
| Raw image-derived features | Mint recipient address |
| | SBT “Verified Human” flag |

---

## Roadmap

- [ ] Replace synthetic embeddings with MediaPipe offline pipeline  
- [ ] Deploy verifier + Soulbound Token on testnet  
- [ ] Local web UI: scan → prove → submit  

---

## References

- [Project 2](../Project%202/README.md) — TrustAgent credit scorer boilerplate  
- [../README.md](../README.md) — common ezkl errors  
- [EZKL docs](https://docs.ezkl.xyz/)
