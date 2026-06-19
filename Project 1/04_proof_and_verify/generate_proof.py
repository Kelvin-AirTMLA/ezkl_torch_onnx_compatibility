"""
Proof-of-Scan — compile circuit, witness, prove, verify, EVM verifier export.
"""

from __future__ import annotations

import json
from pathlib import Path

import ezkl

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ONNX_PATH = PROJECT_ROOT / "02_model_export" / "identity_vault.onnx"
SETTINGS_PATH = PROJECT_ROOT / "03_circuit_generation" / "settings.json"
INPUT_JSON = PROJECT_ROOT / "03_circuit_generation" / "input.json"
CIRCUIT_PATH = PROJECT_ROOT / "04_proof_and_verify" / "network.ezkl"
WITNESS_PATH = PROJECT_ROOT / "04_proof_and_verify" / "witness.json"
PROOF_PATH = PROJECT_ROOT / "04_proof_and_verify" / "network.proof"
VK_PATH = PROJECT_ROOT / "04_proof_and_verify" / "vk.key"
PK_PATH = PROJECT_ROOT / "04_proof_and_verify" / "pk.key"
SRS_PATH = PROJECT_ROOT / "04_proof_and_verify" / "kzg.srs"
VERIFIER_SOL = PROJECT_ROOT / "04_proof_and_verify" / "IdentityVaultVerifier.sol"
VERIFIER_ABI = PROJECT_ROOT / "04_proof_and_verify" / "IdentityVaultVerifier.abi"


def ensure_srs() -> None:
    if not SRS_PATH.exists():
        ezkl.get_srs(str(SETTINGS_PATH), srs_path=str(SRS_PATH))


def compile_if_needed() -> None:
    if CIRCUIT_PATH.exists():
        return
    ezkl.compile_circuit(str(ONNX_PATH), str(CIRCUIT_PATH), str(SETTINGS_PATH))


def setup_keys() -> None:
    if VK_PATH.exists() and PK_PATH.exists():
        return
    ensure_srs()
    ezkl.setup(str(CIRCUIT_PATH), str(VK_PATH), str(PK_PATH), str(SRS_PATH))


def main() -> None:
    if not INPUT_JSON.exists():
        raise FileNotFoundError(
            f"Missing {INPUT_JSON}. Run 03_circuit_generation/compile_circuit.py first."
        )

    compile_if_needed()
    setup_keys()

    ezkl.gen_witness(
        data=str(INPUT_JSON),
        model=str(CIRCUIT_PATH),
        output=str(WITNESS_PATH),
    )

    ezkl.prove(
        witness=str(WITNESS_PATH),
        model=str(CIRCUIT_PATH),
        pk_path=str(PK_PATH),
        proof_path=str(PROOF_PATH),
        srs_path=str(SRS_PATH),
    )

    verified = ezkl.verify(
        proof_path=str(PROOF_PATH),
        settings_path=str(SETTINGS_PATH),
        vk_path=str(VK_PATH),
        srs_path=str(SRS_PATH),
    )

    try:
        ezkl.create_evm_verifier(
            vk_path=str(VK_PATH),
            settings_path=str(SETTINGS_PATH),
            sol_code_path=str(VERIFIER_SOL),
            abi_path=str(VERIFIER_ABI),
            srs_path=str(SRS_PATH),
            reusable=False,
        )
        evm_status = "generated"
    except Exception as exc:
        evm_status = f"skipped ({exc})"

    summary = {
        "witness": str(WITNESS_PATH),
        "proof": str(PROOF_PATH),
        "proof_size_bytes": PROOF_PATH.stat().st_size if PROOF_PATH.exists() else 0,
        "verified_locally": bool(verified),
        "evm_verifier": evm_status,
    }
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
