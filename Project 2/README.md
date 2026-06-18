# Project 2: Verifiable Algorithmic Insurance (DeFi Risk Assessor)

Automates high-stakes business insurance processing without trusting a central corporate adjuster. A decentralized insurance pool releases payouts only when an AI model’s decision is backed by a valid zk-SNARK proof — not a human signature or opaque spreadsheet.

---

## The problem

Traditional insurance at scale depends on centralized adjusters, slow manual review, and trust in institutions that policyholders cannot audit. On-chain insurance cannot run complex floating-point risk models inside the EVM. Uploading raw business telemetry (logistics logs, weather damage reports, supply-chain latency) on-chain exposes competitive and operational secrets.

---

## How it works

### Off-chain AI

A **PyTorch** model evaluates real-world business metrics:

- Supply chain latency and delivery logs  
- Logistics failure patterns  
- Local weather / damage indicators  
- Historical loss-event patterns  

The model outputs a **payout eligibility score** or binary decision: does this claim meet the policy’s mathematical threshold?

### Cryptographic layer (EZKL)

1. Export the model to **ONNX** with fixed, static input shapes.  
2. Run the **EZKL pipeline**: `gen_settings` → `compile_circuit` → `setup` → `gen_witness` → `prove`.  
3. Quantize floating-point metrics to the integer field the circuit expects.  
4. Produce a lightweight **zk-SNARK proof** that the model was executed correctly on the submitted (private) inputs.

### On-chain settlement

A **decentralized insurance pool** smart contract:

1. Receives the proof and public inputs (e.g. policy ID, claim window, payout tier — not raw logs).  
2. Calls an **EZKL-generated Solidity verifier**.  
3. If verification succeeds and the public inputs match an open claim, the contract **automatically releases** the insurance payout from the vault.

---

## Why this is production-shaped (not a demo CRUD app)

| Property | Benefit |
|----------|---------|
| Trustless adjudication | No adjuster can silently override the model |
| Private inputs | Raw business data never hits the chain |
| Auditable logic | Model + circuit are versioned; proofs bind to a specific policy ruleset |
| Automated payouts | Valid proof → vault release, no manual wire transfer |

---

## Architecture (planned)

```
├── 01_environment_setup/     # Python, EZKL CLI, Hardhat/Foundry
├── 02_model_export/          # PyTorch risk model → ONNX
├── 03_circuit_generation/    # settings.json, network.ezkl, SRS
├── 04_proof_and_verify/      # witness, proof, local verify
└── 05_on_chain/              # verifier contract, insurance pool, payout logic
```

---

## Tech stack

| Layer | Tool |
|-------|------|
| Model | PyTorch |
| Export | ONNX |
| Proving | EZKL (Halo2 / KZG) |
| Chain | EVM (verifier via `create-evm-verifier`) |
| Indexing (optional) | The Graph, event listeners |

---

## YouTube angle

Show the full loop: **messy real-world floats → quantized circuit → proof → automatic vault release**. Contrast with “oracle posts a boolean” — here the viewer sees *why* zkML matters for DeFi insurance.

---

## Roadmap

- [ ] Define policy schema (public vs private inputs)  
- [ ] Train / export risk classifier to ONNX  
- [ ] EZKL compile + prove on sample claim bundle  
- [ ] Deploy verifier + insurance pool on testnet  
- [ ] End-to-end demo: submit claim data → proof → payout  

---

## References

- [EZKL docs](https://docs.ezkl.xyz/)  
- [README.md](../README.md) — errors, triggering code, fixes  
- [reference-pipeline/](../reference-pipeline/) — working end-to-end tutorial  
