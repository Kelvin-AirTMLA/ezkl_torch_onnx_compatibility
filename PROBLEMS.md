# Common problems — Keras → ONNX → ezkl → EVM

A log of errors encountered in this repo, what they mean, and why they happen.

Pipeline:

```
Keras → tf2onnx → network.onnx → gen_settings → compile_circuit → get_srs → setup
  → gen_witness → prove → verify → create-evm-verifier → deploy → web3.js
```

See also: [README.md](./README.md) for installation and setup.

---

## Problem 1: `KeyError: 'keras_tensor_4'` (Sequential vs Functional)

**When:** `tf2onnx.convert.from_keras(model)` with a **Sequential** model.

**Error:**

```
KeyError: 'keras_tensor_4'
```

(The number varies — `keras_tensor_65`, etc. — depending on model depth.)

### What it looks like

```python
model = tf.keras.Sequential([
    tf.keras.layers.Input(shape=(28, 28, 1)),
    tf.keras.layers.Conv2D(32, (3, 3), activation="relu"),
    tf.keras.layers.Flatten(),
    tf.keras.layers.Dense(10, activation="softmax"),
])

onnx_model, _ = tf2onnx.convert.from_keras(model)  # KeyError here
```

### What `keras_tensor_4` means

Keras auto-generates internal names for tensors that are not explicitly named: `keras_tensor_0`, `keras_tensor_1`, `keras_tensor_4`, and so on. These are bookkeeping labels for anonymous intermediate tensors — not layer names like `dense` or `conv2d`.

### What `from_keras` actually does

`tf2onnx.convert.from_keras` does not read Keras layer objects directly. It:

1. **Traces** the model into a TensorFlow computation graph (`concrete_function`)
2. Builds a **rename map** between traced tensor names and Keras logical names
3. Reads **`model.output_names`** to decide which traced tensors are outputs
4. Looks up each output name in that map:

```python
output_names = [reverse_lookup[out] for out in model_out_names]
```

`KeyError: 'keras_tensor_4'` means: the model claims an output is named `keras_tensor_4`, but that string **does not appear** in the trace’s rename map. The converter cannot find the output tensor it was told to export.

### Why Sequential breaks more often

**Sequential** builds an implicit chain — you stack layers without declaring which tensor is the output. Keras wires layers together and assigns auto-generated names to intermediates. The model’s `output_names` may say `keras_tensor_4`, but when `tf2onnx` traces the model, the traced graph registers the same output under a **different** internal name. The two naming schemes do not match.

**Functional API** makes inputs and outputs explicit:

```python
inputs = tf.keras.Input(shape=(28, 28, 1))
x = tf.keras.layers.Conv2D(32, (3, 3), activation="relu")(inputs)
x = tf.keras.layers.Flatten()(x)
outputs = tf.keras.layers.Dense(10, activation="softmax")(x)
model = tf.keras.Model(inputs=inputs, outputs=outputs)
```

### Fix

Use the **Functional API** when exporting to ONNX. See `model.py` in this repo.

Related issues: [tensorflow-onnx #2319](https://github.com/onnx/tensorflow-onnx/issues/2319), [#2348](https://github.com/onnx/tensorflow-onnx/issues/2348), [#2448](https://github.com/onnx/tensorflow-onnx/issues/2448).

---

## Problem 2: `Reshape ToTypedTranslator` — why Flatten is the problem

**When:** `ezkl.gen_settings("network.onnx")` after a successful ONNX export.

**Error:**

```
RuntimeError: Failed to generate settings: [graph] [tract] Translating node #17 
"functional_1/flatten_1/Reshape" Reshape ToTypedTranslator
```

During `gen_settings`, ezkl uses **tract** to infer **concrete tensor shapes**. It fails on the **Reshape** node from Keras **`Flatten()`** because the target shape is not known at compile time.

Keras `Flatten()` is exported as:

```
Shape → Slice → Concat (with -1) → Reshape
```

That works in ONNX Runtime but not in ezkl’s fixed-shape ZK circuit builder.

### Fix

Replace `Flatten()` with a fixed `Reshape((21632,))` (for this model) and fix the batch dimension (Problem 3).

---

## Problem 3: Dynamic batch size (`unk__32`)

**When:** ONNX export or `ezkl.gen_settings`.

Default Keras input:

```python
inputs = tf.keras.Input(shape=(28, 28, 1))  # batch=None
```

produces ONNX input batch `(0, 'unk__32')` — symbolic, not fixed.

### Fix directions

1. `batch_size=1` on `Input`
2. **`input_signature` on `from_keras`** (required — see Problem 4)
3. Fixed `Reshape` instead of `Flatten`
4. Optional ONNX post-process to set `dim_value = 1`

### Confirm

```bash
python -c "
import onnx
m = onnx.load('network.onnx')
d = m.graph.input[0].type.tensor_type.shape.dim[0]
print('batch:', d.dim_value, d.dim_param)
"
```

Want `batch: 1` with empty `dim_param`, not `unk__32`.

---

## Problem 4: `batch_size=1` alone is not enough

**When:** You set `batch_size=1` on `Input` but still get Problem 2 or dynamic batch in ONNX.

**Cause:** `tf2onnx.convert.from_keras(model)` without `input_signature` can still export a symbolic batch even when Keras has `batch_size=1`.

### Fix

```python
input_signature = [tf.TensorSpec([1, 28, 28, 1], tf.float32, name="input")]
onnx_model, _ = tf2onnx.convert.from_keras(model, input_signature=input_signature)
```

With this, Flatten/Reshape uses a **constant** shape tensor and `gen_settings` succeeds.

---

## Problem 5: Python environment — `ModuleNotFoundError: tf2onnx`

**When:** `import tf2onnx` or running `model.py` fails despite `pip install tf2onnx` succeeding.

**Error:**

```
ModuleNotFoundError: No module named 'tf2onnx'
```

### Cause

Packages were installed in the **venv**, but the script was run with a **different Python**:

```bash
/opt/homebrew/bin/python3 model.py   # wrong — bypasses venv
python model.py                      # correct — uses .venv when activated
```

`pip install` and `python model.py` must use the **same interpreter**.

### Fix

```bash
source .venv/bin/activate
which python   # should be .../ezkl/.venv/bin/python
python model.py
```

In the IDE, set the interpreter to `.venv/bin/python`.

---

## Problem 6: TensorFlow not available on Python 3.14

**When:** `pip install tensorflow` in a Python 3.14 venv.

**Error:**

```
ERROR: No matching distribution found for tensorflow
```

TensorFlow has no wheels for 3.14 (at time of writing). Use **Python 3.11 or 3.13**:

```bash
/opt/homebrew/bin/python3.13 -m venv .venv
source .venv/bin/activate
pip install tensorflow tf2onnx ezkl onnx
```

---

## Problem 7: `pip install ezkl` vs the `ezkl` CLI command

**When:** `pip install ezkl` succeeds but `ezkl` in terminal gives `command not found`.

These are **different installs**:

| Install | Gives you |
|---------|-----------|
| `pip install ezkl` | Python library (`import ezkl`) |
| GitHub release binary / install script | Shell command `ezkl` |

No conflict — but do not expect `pip` to add a CLI binary.

---

## Problem 8: ezkl CLI install fails on macOS (latest release)

**When:** `curl .../install_ezkl_cli.sh | bash` stops after:

```
Platform: macos
Architecture: aarch64
```

**Cause:** Latest release (e.g. v23.0.5) may ship **no macOS binary**. The script finds no download URL and exits silently; `~/.ezkl` stays empty.

### Fix

Pin a release that includes macOS assets:

```bash
curl -s https://raw.githubusercontent.com/zkonduit/ezkl/main/install_ezkl_cli.sh | bash -s v23.0.3
```

See [README.md](./README.md) for manual download URLs.

---

## Problem 9: `brew install ezkl` / `cargo install ezkl`

| Command | Result |
|---------|--------|
| `brew install ezkl` | No Homebrew formula |
| `cargo install ezkl` | Not published on crates.io |

Use the GitHub release binary or build from a cloned repo.

---

## Problem 10: `failed to load srs from kzg.srs`

**When:** `ezkl.setup(..., "kzg.srs")`.

**Error:**

```
RuntimeError: Failed to run setup: [srs] failed to load srs from kzg.srs
```

**Cause:** `kzg.srs` does not exist yet. `setup` reads SRS; it does not create it.

### Fix

Before `setup`:

```bash
ezkl get-srs -S settings.json --srs-path kzg.srs
```

Python:

```python
ezkl.get_srs("settings.json", srs_path="kzg.srs")
```

Note the API: `get_srs(settings_path, logrows=None, srs_path=None)` — not `(settings_path, srs_path)` as positional strings only; use keyword `srs_path=` to avoid `TypeError: logrows: 'str' object cannot be interpreted as an integer`.

---

## Problem 11: `gen_witness` — wrong paths and missing `input.json`

**When:** `ezkl.gen_witness()` with no arguments.

**Errors:**

```
(model.compiled) No such file or directory
(input.json) No such file or directory
```

### Cause

Defaults do not match this project:

| Argument | Default | This repo |
|----------|---------|-----------|
| `data` | `input.json` | must be created |
| `model` | `model.compiled` | **`network.ezkl`** |

### Fix

```python
ezkl.gen_witness(
    data="input.json",
    model="network.ezkl",
    output="witness.json",
)
```

Create `input.json` first (Problem 12).

---

## Problem 12: `input.json` format — flat vs nested

**When:** `gen_witness` with nested array `input_data`.

**Error:**

```
failed to deserialize FileSourceInner
```

### Cause

ezkl expects **flat** `input_data` for this model, not nested `[1][28][28][1]` arrays.

### Fix

```python
json.dump(
    {
        "input_data": [sample_input.reshape(-1).tolist()],
        "output_data": [sample_output.reshape(-1).tolist()],
    },
    f,
)
```

Shapes must match `settings.json` (`[1,28,28,1]` input, `[1,10]` output).

---

## Problem 13: `prove()` needs explicit arguments

**When:** `ezkl.prove()` with no arguments after fixing witness.

Pass paths explicitly:

```python
ezkl.prove(
    witness="witness.json",
    model="network.ezkl",
    pk_path="pk.key",
    proof_path="proof.json",
    srs_path="kzg.srs",
)
ezkl.verify(
    proof_path="proof.json",
    settings_path="settings.json",
    vk_path="vk.key",
    srs_path="kzg.srs",
)
```

---

## Problem 14: Pipeline is very slow

**When:** Running full `model.py` every time.

**Cause:**

1. Script re-runs **compile_circuit**, **setup**, and **prove** from scratch each time.
2. Circuit is large (~**914k rows** in `settings.json`) — Conv + Dense(21632→10) + softmax is heavy in ZK.
3. **`prove`** is CPU-bound; no GPU acceleration for ezkl proving on this setup.

### Mitigation

- Comment out compile/setup on repeat runs; only re-run `gen_witness` + `prove`.
- Use a smaller model while learning (skip conv/softmax at first).
- Expect **minutes** per prove on a laptop for this circuit size.

---

## Problem 15: CLI vs Python version mismatch

**When:** Using both `ezkl` CLI and `pip install ezkl`.

**Warning:**

```
Version mismatch: CLI version is 23.0.3 but artifact version is 23.0.5
```

Mac CLI was pinned to v23.0.3 (last release with macOS binary); Python package may be newer. Align versions when possible to avoid subtle incompatibilities.

---

## Problem 16: `create-evm-verifier` — SRS not found

**When:** `ezkl create-evm-verifier` with no flags.

**Error:**

```
[srs] failed to load srs from ~/.ezkl/srs/kzg17.srs
```

**Cause:** Default SRS path is `~/.ezkl/srs/kzg{logrows}.srs` (e.g. `kzg17.srs` from `logrows: 17`). Project SRS is `./kzg.srs` from `get_srs`.

### Fix

```bash
ezkl create-evm-verifier \
  --srs-path kzg.srs \
  -S settings.json \
  --vk-path vk.key \
  --sol-code-path evm_deploy.sol
```

Requires **`vk.key`** from `setup` first. Outputs `evm_deploy.sol` and `verifier_abi.json`.

---

## Problem 17: `create-evm-verifier` — missing `solc`

**When:** After fixing SRS path.

**Error:**

```
[eth] svm error: error sending request for url (https://binaries.soliditylang.org/...)
```

ezkl auto-installs the required **Solidity compiler** via `svm`. Needs **network access**. Install `solc` manually (e.g. `solc-select`) if the download fails.

---

## Problem 18: Deploying contracts vs running `web3.js`

**When:** Trying to “deploy” `web3.js`.

**Clarification:**

| Artifact | Deployed? | Tool |
|----------|-----------|------|
| `evm_deploy.sol` (verifier) | Yes — on-chain | Hardhat, Foundry, or Remix |
| `web3.js` | No — **run locally** | `node web3.js` |

Order: deploy verifier → put address in `web3.js` → `npm install web3 && node web3.js`.

Raw `proof.json` / `input.json` may not match the verifier’s expected calldata — use ezkl’s EVM encoding commands if `verify()` reverts or fails.

---

## Quick reference

| Error / symptom | Stage | Fix |
|-----------------|-------|-----|
| `KeyError: 'keras_tensor_N'` | `tf2onnx` | Functional API |
| `Reshape ToTypedTranslator` | `gen_settings` | Fixed `Reshape` + static batch |
| Batch still `unk__32` | ONNX export | `input_signature` on `from_keras` |
| `ModuleNotFoundError: tf2onnx` | Python | Same venv for pip and `python` |
| No TensorFlow on pip | Python 3.14 | venv on 3.11 or 3.13 |
| `command not found: ezkl` after pip | Install | CLI binary separate from pip |
| Installer stops at `aarch64` | macOS CLI | Pin `v23.0.3` or manual download |
| `failed to load srs from kzg.srs` | `setup` | `get_srs` before `setup` |
| `get_srs` TypeError on logrows | Python API | `get_srs("settings.json", srs_path="kzg.srs")` |
| `model.compiled` not found | `gen_witness` | `model="network.ezkl"` |
| `input.json` not found | `gen_witness` | Create flat-format JSON |
| deserialize error on input | `gen_witness` | Flat `input_data`, not nested |
| Everything slow | full pipeline | Skip re-compile; smaller model for dev |
| `kzg17.srs` not found | `create-evm-verifier` | `--srs-path kzg.srs` |
| solc / svm network error | EVM verifier | Network or install solc manually |
| Version mismatch 23.0.3 / 23.0.5 | CLI + Python | Align ezkl versions |
