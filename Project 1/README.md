# Project 1: Proof-of-Scan Biometric Identity Vault

A local web or mobile app that verifies a user's identity using open-source facial landmarks (e.g. MediaPipe) **offline**, then uses EZKL to prove the inference on-chain — without ever leaking raw biometrics, face maps, or photos.

**Recommended starter project** for YouTube / engineering demos: it directly tackles online privacy and the **proof-of-human** problem.

---

## The problem

Web3 protocols need to know *“this wallet belongs to a unique human”* without:

- Uploading face photos or biometric templates to a chain  
- Trusting a centralized KYC provider with permanent data retention  
- Exposing geometric face embeddings in public calldata  

Blockchains are transparent. Biometrics are irreversible if leaked. The design must prove identity **without revealing identity data**.

---

## How it works

### Off-chain AI (local only)

1. User captures a face scan on device (camera).  
2. An open-source **facial landmarks / geometric embedding** model (MediaPipe, similar) runs **entirely offline**.  
3. The model outputs a classification or embedding match (e.g. “matches enrolled template”) — never sent raw to the network.

### Cryptographic layer (EZKL)

1. The inference graph is exported to **ONNX** with **fixed, static input shapes**.  
2. **EZKL** compiles the model into a zk-SNARK circuit.  
3. User inputs stay in the **witness** (private).  
4. The prover generates a proof: *“this model, on these private inputs, produced this public result.”*

### On-chain settlement

1. The proof is submitted to **Ethereum** (or another EVM chain).  
2. An **EZKL-generated Solidity verifier** checks the proof is mathematically valid.  
3. On success, the contract mints a **Soulbound Token (SBT)** — a non-transferable **“Verified Human”** badge bound to the user’s wallet.

### The breakthrough

The user proves **unique human identity** to a protocol **without** publishing:

- Raw biometric data  
- Face maps or landmark coordinates  
- Photos or reversible embeddings on-chain  

---

## Why this is production-shaped (not a demo CRUD app)

| Property | Benefit |
|----------|---------|
| Privacy by architecture | Witness holds biometrics; chain sees proof only |
| Sybil resistance | Protocols filter bots without centralized document storage |
| Soulbound outcome | Verified status cannot be sold or transferred |
| Offline-first | Scan and prove locally; chain only verifies math |

---

## Architecture (planned)

```
├── 01_environment_setup/     # Python, EZKL CLI, mobile/web dev env
├── 02_model_export/          # Landmarks / embedding model → ONNX
├── 03_circuit_generation/    # settings.json, network.ezkl, SRS
├── 04_proof_and_verify/      # witness, proof, local verify
├── 05_client_app/            # Local capture UI (web or mobile)
└── 06_on_chain/              # verifier contract, SBT mint logic
```

---

## Tech stack

| Layer | Tool |
|-------|------|
| Biometrics | MediaPipe (or similar open-source landmarks) |
| Model | PyTorch → ONNX |
| Proving | EZKL |
| Chain | EVM + SBT (EIP-5192 style soulbound) |
| Client | Local web app or mobile shell |

---

## Public vs private inputs (design sketch)

| Private (witness) | Public (on-chain) |
|-------------------|-------------------|
| Landmark coordinates / embedding | Proof bytes |
| Raw image-derived features | Model version hash |
| Enrollment comparison internals | Mint recipient address |
| | Optional: nullifier / one-human-one-SBT flag |

Exact schema to be fixed before circuit compile — see [../README.md](../README.md) for static-shape requirements.

---

## YouTube angle

Strong narrative hook: **“Prove you’re human without showing your face to the blockchain.”** Demo the full arc: camera → local model → EZKL proof → SBT mint. Contrast with traditional KYC upload flows.

---

## Roadmap

- [ ] Landmarks model → ONNX with fixed input shape  
- [ ] EZKL compile + prove on synthetic face tensor  
- [ ] Deploy verifier + SBT contract on testnet  
- [ ] Minimal local web UI: scan → prove → submit  
- [ ] Document threat model (replay, enrollment, liveness)  

---

## Other projects in this repo

- [Project 2](../Project%202/README.md) — Verifiable algorithmic insurance  
- [Project 3](../Project%203/README.md) — Secure federated medical DAO  

## References

- [EZKL docs](https://docs.ezkl.xyz/)  
- [../README.md](../README.md) — errors, triggering code, fixes  
- [../reference-pipeline/](../reference-pipeline/) — working Keras → ezkl tutorial  
