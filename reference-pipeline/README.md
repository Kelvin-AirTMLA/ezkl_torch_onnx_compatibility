# Reference pipeline

End-to-end **Keras → ONNX → EZKL → prove → EVM** tutorial from this repo. All scripts, artifacts, and contracts for that workflow live here.

## Contents

| Path | Purpose |
|------|---------|
| `model.py` | Export model, run full ezkl pipeline |
| `web3.js` | Call on-chain verifier (after deploy) |
| `package.json` | Hardhat / Node deps |
| `contracts/` | `evm_deploy.sol` (generated verifier), `EZKLTestContract.sol` (example consumer) |
| `*.onnx`, `*.ezkl`, `*.key`, `*.srs`, `*.json` | Generated artifacts (gitignored) |

## Run

```bash
cd reference-pipeline
source ../.venv/bin/activate
python model.py
```

Generate verifier contract (from this directory):

```bash
ezkl create-evm-verifier \
  --srs-path kzg.srs \
  -S settings.json \
  --vk-path vk.key \
  --sol-code-path contracts/evm_deploy.sol
```

## Docs

- [../README.md](../README.md) — errors, triggering code, fixes  

## App projects

Production app specs (not implemented here yet):

- [../Project 1/README.md](../Project%201/README.md) — Proof-of-Scan biometric vault  
- [../Project 2/README.md](../Project%202/README.md) — Verifiable algorithmic insurance  
- [../Project 3/README.md](../Project%203/README.md) — Federated medical DAO  
