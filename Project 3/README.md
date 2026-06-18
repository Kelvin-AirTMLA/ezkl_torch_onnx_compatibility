# Project 3: Secure Federated Medical DAO (Privacy-Preserving AI)

Lets hospitals and research labs collaborate on medical AI and earn web3 rewards **without** uploading patient scans or violating privacy laws (HIPAA and similar). Nodes prove they ran the agreed computation correctly; the DAO never sees raw imagery.

---

## The problem

Federated learning and multi-site medical research need shared model improvement, but:

- **Patient imagery and diagnostics cannot go on a public chain.**  
- **Hospitals cannot trust each other’s self-reported gradients** without verification.  
- **Central coordinators** become single points of failure and compliance risk.

A medical DAO needs: *“We verified your local update was computed correctly”* — not *“Send us your DICOM files.”*

---

## How it works

### Off-chain nodes (hospitals / labs)

Each participant runs a **local diagnostic node**:

- Holds anonymous or institution-local medical imagery datasets.  
- Runs inference or local training steps on a **unified neural network layout** (same ONNX graph for every node).  
- Never uploads raw scans to the coordinator or chain.

### Cryptographic layer (EZKL)

Instead of sending weights or data in the clear, each node:

1. Executes the model / validation checks locally.  
2. Uses **EZKL** to generate a proof that:  
   - The local computation matched the canonical model graph.  
   - Declared validation checks (shape, bounds, aggregation rules) were satisfied.  
3. Submits only the **proof + agreed public inputs** (node ID, epoch, contribution hash).

### On-chain coordination (DAO)

A **coordinating DAO smart contract**:

1. Verifies incoming proofs from all nodes via EZKL Solidity verifiers.  
2. Aggregates **verified** contributions (e.g. weight updates, score commitments).  
3. **Distributes token payouts** to participating hospitals based on verified compute contribution.  
4. Updates the global model commitment on-chain without ever storing patient data.

---

## Why this is production-shaped (not a demo CRUD app)

| Property | Benefit |
|----------|---------|
| HIPAA-aligned design | Raw PHI stays local; chain sees proofs only |
| Verifiable federation | Free-riding and fake gradients are cryptographically excluded |
| Incentive alignment | DAO tokens pay verified contributors, not self-reported claims |
| Composable governance | Model upgrades voted by stakeholders; proofs bind to model version |

---

## Architecture (planned)

```
├── 01_environment_setup/     # Python, EZKL, node CLI, wallet keys
├── 02_model_export/          # Shared diagnostic model → ONNX
├── 03_circuit_generation/      # Per-node circuit artifacts, settings
├── 04_proof_and_verify/      # Local witness + proof generation
├── 05_federation_protocol/   # Proof submission, aggregation rules
└── 06_dao_contracts/         # Verifier, registry, rewards, model commitment
```

---

## Tech stack

| Layer | Tool |
|-------|------|
| Model | PyTorch → ONNX (shared graph) |
| Proving | EZKL per-node proofs |
| Coordination | DAO smart contracts (EVM) |
| Storage (off-chain) | IPFS / encrypted object store for *non-PHI* metadata only |
| Compliance | Local DICOM handling; no raw scans on-chain by design |

---

## Design constraints (non-negotiable)

1. **No raw patient imagery on-chain.**  
2. **Fixed model version** per training epoch — proofs must reference a committed ONNX hash.  
3. **Public inputs minimized** — only what the DAO needs to score contribution.  
4. **Institution identity** via wallet / allowlist, separate from patient identity.

---

## YouTube angle

Walk through: *“Hospital A proves it ran the same model as Hospital B, without either leaking a single scan.”* Strong hook for privacy + web3 + ML engineering audiences.

---

## Roadmap

- [ ] Define unified model architecture and public input schema  
- [ ] Single-node EZKL proof on sample (synthetic) medical tensor  
- [ ] Multi-node proof verification mock (local)  
- [ ] DAO contract: verify + reward + model commitment  
- [ ] Testnet demo with two mock “hospitals”  

---

## References

- [EZKL docs](https://docs.ezkl.xyz/)  
- [README.md](../README.md) — errors, triggering code, fixes  
- [reference-pipeline/](../reference-pipeline/) — working end-to-end tutorial  
- [Project 1](../Project%201/README.md) — Proof-of-Scan biometric vault (complementary identity use case)  
