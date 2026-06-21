# ezkl — problems, pitfalls & reference

A log of errors encountered in this repo, what they mean, and why they happen.

Each problem includes **triggering code** — the exact snippet or command that produced the error.

Official install docs: [docs.ezkl.xyz/getting-started/installation](https://docs.ezkl.xyz/getting-started/installation)

---

## Workspace layout

```
ezkl/
├── README.md              # This file — errors, triggering code, fixes
├── Project 1/             # Proof-of-Scan biometric vault
├── Project 2/             # Verifiable algorithmic insurance
├── Project 3/             # Federated medical DAO
└── reference-pipeline/    # Working Keras → ONNX → ezkl tutorial
```

Run the tutorial from `reference-pipeline/`. See [reference-pipeline/README.md](./reference-pipeline/README.md).

---

Pipeline:

```
Keras → tf2onnx → network.onnx → gen_settings → compile_circuit → get_srs → setup
  → gen_witness → prove → verify → create-evm-verifier → deploy → web3.js
```

---

## Problem 1: `KeyError: 'keras_tensor_N'` (Sequential vs Functional)

**When:** `tf2onnx.convert.from_keras(model)` with a **Sequential** model.

**Error:**

```
KeyError: 'keras_tensor_4'
```

The exact number varies by session (`keras_tensor_23`, `keras_tensor_4`, etc.) — it is **not** the input count. Keras auto-increments a global counter for symbolic tensors as the graph is built.

### Triggering code

```python
model = tf.keras.Sequential([
    tf.keras.layers.Input(shape=(28, 28, 1)),
    tf.keras.layers.Conv2D(32, (3, 3), activation="relu"),
    tf.keras.layers.Flatten(),
    tf.keras.layers.Dense(10, activation="softmax"),
])

onnx_model, _ = tf2onnx.convert.from_keras(model)  # KeyError: 'keras_tensor_N'
```

### Why it fails

`keras_tensor_N` is **not a layer** — it is an auto-generated name for a **symbolic output tensor** (data flowing between layers).

During export, tf2onnx (`convert.py`):

1. **Traces** the model → a TensorFlow `ConcreteFunction` with its own internal tensor names.
2. **Builds** `tensors_to_rename` from the trace (Keras/structured name ↔ traced TF name).
3. **Inverts** it to `reverse_lookup` (Keras name → traced TF name).
4. **Looks up** the model's output name in `reverse_lookup` to find the traced output.

The crash is step 4: the name tf2onnx looks up is not a key in `reverse_lookup`.

**Where tf2onnx gets the output name (Sequential, current Keras/TF):**

Sequential has `output`, `outputs`, and `output_shape` — but **no** `output_names` attribute. tf2onnx falls back in `_get_output_names()`:

```python
model.outputs[0].name           # e.g. 'keras_tensor_23:0'
.split('/')[0]                  # → 'keras_tensor_23'  ← lookup key
```

Then at line ~529: `reverse_lookup['keras_tensor_23']` → **KeyError**, because the trace registered different keys (e.g. from `concrete_func.structured_outputs`).

Functional API usually works because Keras tensor names and traced graph names **align** after export. Sequential often does not.

**Common false lead:** printing Functional API tensors (`keras_tensor_24`–`27`) while exporting a Sequential `model` — those are different graphs; only the object passed to `from_keras(model)` matters.

### Fixed code

Use the Functional API and wrap with `tf.keras.Model`:

```python
inputs = tf.keras.Input(shape=(28, 28, 1))
x = tf.keras.layers.Conv2D(32, (3, 3), activation="relu")(inputs)
x = tf.keras.layers.Flatten()(x)
outputs = tf.keras.layers.Dense(10, activation="softmax")(x)
model = tf.keras.Model(inputs=inputs, outputs=outputs)

onnx_model, _ = tf2onnx.convert.from_keras(model)  # works
```

For this repo's full ezkl pipeline, also replace `Flatten()` with explicit `Reshape((21632,))` — see Problem 2.

Related issues: [tensorflow-onnx #2319](https://github.com/onnx/tensorflow-onnx/issues/2319), [#2348](https://github.com/onnx/tensorflow-onnx/issues/2348), [#2448](https://github.com/onnx/tensorflow-onnx/issues/2448).

---

## Problem 2: `Reshape ToTypedTranslator` — why Flatten is the problem

**When:** `ezkl.gen_settings("network.onnx")` after exporting with `Flatten()`.

**Error:**

```
RuntimeError: Failed to generate settings: [graph] [tract] Translating node #17 
"functional_1/flatten_1/Reshape" Reshape ToTypedTranslator
```

### Triggering code

```python
inputs = tf.keras.Input(shape=(28, 28, 1))
x = tf.keras.layers.Conv2D(32, (3, 3), activation="relu")(inputs)
x = tf.keras.layers.Flatten()(x)   # exported as dynamic Shape → Concat → Reshape
outputs = tf.keras.layers.Dense(10, activation="softmax")(x)
model = tf.keras.Model(inputs=inputs, outputs=outputs)

onnx_model, _ = tf2onnx.convert.from_keras(model)
with open("network.onnx", "wb") as f:
    f.write(onnx_model.SerializeToString())

ezkl.gen_settings("network.onnx")  # fails on flatten_1/Reshape
```

Also tried (wrong syntax **and** wrong size):

```python
x = tf.keras.layers.Reshape(10)   # missing (x); 10 ≠ 21632 features after Conv2D
outputs = tf.keras.layers.Dense(10, activation="softmax")(x)
```

### Fixed code

```python
x = tf.keras.layers.Reshape((21632,))(x)  # 26×26×32 after Conv2D(3,3) on 28×28
```

Plus static batch (Problems 3–4).

---

## Problem 3: Dynamic batch size (`unk__32`)

**When:** ONNX export without fixed batch.

**Error:** Same as Problem 2, or batch shows as symbolic in ONNX inspection.

### Triggering code

```python
inputs = tf.keras.Input(shape=(28, 28, 1))  # batch=None (default)
# ...
onnx_model, _ = tf2onnx.convert.from_keras(model)
```

ONNX input after export:

```
batch: dim_value=0  dim_param='unk__32'
```

### Confirm

```bash
python -c "
import onnx
m = onnx.load('network.onnx')
d = m.graph.input[0].type.tensor_type.shape.dim[0]
print('batch:', d.dim_value, d.dim_param)
"
```

### Fixed code

See Problem 4 — `batch_size=1` **and** `input_signature`.

---

## Problem 4: `batch_size=1` alone is not enough

**When:** Batch is set in Keras but ONNX still has `unk__32`.

### Triggering code

```python
inputs = tf.keras.Input(shape=(28, 28, 1), batch_size=1)
x = tf.keras.layers.Conv2D(32, (3, 3), activation="relu")(inputs)
x = tf.keras.layers.Reshape((21632,))(x)
outputs = tf.keras.layers.Dense(10, activation="softmax")(x)
model = tf.keras.Model(inputs=inputs, outputs=outputs)

# batch_size=1 in Keras, but tf2onnx still exports dynamic batch:
onnx_model, _ = tf2onnx.convert.from_keras(model)
```

ONNX still shows `unk__32`; `gen_settings` still fails on dynamic Reshape.

### Fixed code

```python
input_signature = [tf.TensorSpec([1, 28, 28, 1], tf.float32, name="input")]
onnx_model, _ = tf2onnx.convert.from_keras(model, input_signature=input_signature)
```

Reshape in ONNX then uses a constant shape tensor; `gen_settings` succeeds.

---

## Problem 5: Python environment — `ModuleNotFoundError: tf2onnx`

**When:** Packages in venv, script run with system Python.

**Error:**

```
ModuleNotFoundError: No module named 'tf2onnx'
```

### Triggering code

```bash
source .venv/bin/activate
pip3 install tf2onnx          # installs into .venv
pip3 install tf2onnx          # Success

/opt/homebrew/bin/python3 model.py   # wrong interpreter — fails
```

Or from IDE Run button with Homebrew Python selected, while pip went to venv.

Also invalid:

```bash
.venv/bin/python -m pip3 install torch
# No module named pip3  — use: python -m pip
```

### Fixed code

```bash
source .venv/bin/activate
which python    # .../ezkl/.venv/bin/python
pip install tf2onnx
python model.py
```

---

## Problem 6: TensorFlow not available on Python 3.14

**When:** venv created on Python 3.14.

**Error:**

```
ERROR: No matching distribution found for tensorflow
```

### Triggering code

```bash
python3.14 -m venv .venv
source .venv/bin/activate
pip install tensorflow   # fails — no wheel for 3.14
```

### Fixed code

```bash
/opt/homebrew/bin/python3.13 -m venv .venv
source .venv/bin/activate
pip install tensorflow tf2onnx ezkl onnx
```

---

## Problem 7: `pip install ezkl` vs the `ezkl` CLI command

**When:** Expecting a shell command after pip.

**Error:**

```
zsh: command not found: ezkl
```

### Triggering code

```bash
pip install ezkl
# Successfully installed ezkl-23.0.5

ezkl --help   # command not found
```

`pip` installs `import ezkl` only — not `/usr/local/bin/ezkl`.

### Fixed code

CLI (macOS, pin version with macOS binary):

```bash
curl -s https://raw.githubusercontent.com/zkonduit/ezkl/main/install_ezkl_cli.sh | bash -s v23.0.3
source ~/.zshenv
ezkl --help
```

---

## Problem 8: ezkl CLI install fails on macOS (latest release)

**When:** Default installer with no version pin.

**Error:** Script stops after `Architecture: aarch64` with no download message; `~/.ezkl` empty.

### Triggering code

```bash
curl https://raw.githubusercontent.com/zkonduit/ezkl/main/install_ezkl_cli.sh | bash
# Platform: macos
# Architecture: aarch64
# (nothing else — silent exit)
```

Latest release (e.g. v23.0.5) had no macOS asset at time of writing.

### Fixed code

```bash
curl -s https://raw.githubusercontent.com/zkonduit/ezkl/main/install_ezkl_cli.sh | bash -s v23.0.3
source ~/.zshenv
```

---

## Problem 9: `brew install ezkl` / `cargo install ezkl`

### Triggering code

```bash
brew install ezkl
# Warning: No available formula with the name "ezkl"

cargo install ezkl --locked
# error: could not find `ezkl` in registry `crates-io`
```

No fix via these commands — use GitHub release binary (Problem 8).

---

## Problem 10: `failed to load srs from kzg.srs`

**When:** `setup` before SRS exists.

**Error:**

```
RuntimeError: Failed to run setup: [srs] failed to load srs from kzg.srs
```

### Triggering code

```python
ezkl.gen_settings("network.onnx")
ezkl.compile_circuit("network.onnx", "network.ezkl", "settings.json")
ezkl.setup("network.ezkl", "vk.key", "pk.key", "kzg.srs")  # kzg.srs does not exist
```

### Fixed code

```python
ezkl.get_srs("settings.json", srs_path="kzg.srs")
ezkl.setup("network.ezkl", "vk.key", "pk.key", "kzg.srs")
```

---

## Problem 11: `get_srs` — wrong argument order

**When:** Passing `srs_path` as second positional argument.

**Error:**

```
TypeError: argument 'logrows': 'str' object cannot be interpreted as an integer
```

### Triggering code

```python
ezkl.get_srs("settings.json", "kzg.srs")  # "kzg.srs" bound to logrows, not srs_path
```

### Fixed code

```python
ezkl.get_srs("settings.json", srs_path="kzg.srs")
```

---

## Problem 12: `gen_witness` — wrong paths and missing `input.json`

**When:** `gen_witness()` with defaults.

**Errors:**

```
(model.compiled) No such file or directory
(input.json) No such file or directory
```

### Triggering code

```python
ezkl.gen_witness()  # defaults: data=input.json, model=model.compiled
```

```bash
ezkl gen-witness   # same defaults
```

This project uses `network.ezkl`, not `model.compiled`, and had no `input.json`.

### Fixed code

```python
ezkl.gen_witness(
    data="input.json",
    model="network.ezkl",
    output="witness.json",
)
```

---

## Problem 13: `input.json` format — flat vs nested

**When:** Nested array layout in `input_data`.

**Error:**

```
failed to deserialize FileSourceInner
```

### Triggering code

```python
sample_input = np.random.random((1, 28, 28, 1)).astype(np.float32)
json.dump(
    {"input_data": sample_input.tolist(), "output_data": sample_output.tolist()},
    f,
)
ezkl.gen_witness(data="input.json", model="network.ezkl", output="witness.json")
# fails — nested [1][28][28][1] layout
```

### Fixed code

```python
json.dump(
    {
        "input_data": [sample_input.reshape(-1).tolist()],
        "output_data": [sample_output.reshape(-1).tolist()],
    },
    f,
)
```

---

## Problem 14: `prove()` needs explicit arguments

**When:** Calling `prove()` with no paths.

### Triggering code

```python
ezkl.gen_witness(data="input.json", model="network.ezkl", output="witness.json")
ezkl.prove()   # missing witness, model, pk_path, srs_path
```

### Fixed code

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

## Problem 15: Pipeline is very slow

**When:** Running the full script on every iteration.

### Triggering code

```python
# entire pipeline every run — no caching / skip logic
ezkl.gen_settings("network.onnx")
ezkl.compile_circuit("network.onnx", "network.ezkl", "settings.json")
ezkl.setup("network.ezkl", "vk.key", "pk.key", "kzg.srs")
ezkl.gen_witness(...)
ezkl.prove(...)   # ~914k rows in settings.json — minutes on CPU
```

`settings.json` shows `"num_rows": 913630` for this model (Conv + Dense(21632→10) + softmax).

### Mitigation

Only re-run witness + prove after artifacts exist; use a smaller model while learning.

---

## Problem 16: CLI vs Python version mismatch

**When:** Mixing Homebrew/CLI binary and pip package.

### Triggering code

```bash
ezkl gen-witness -D input.json -M network.ezkl -O witness.json
# [W] Version mismatch: CLI version is 23.0.3 but artifact version is 23.0.5
```

CLI pinned to v23.0.3 (macOS); Python `pip install ezkl` is v23.0.5.

---

## Problem 17: `create-evm-verifier` — SRS not found

**When:** Bare command, no `--srs-path`.

**Error:**

```
[srs] failed to load srs from ~/.ezkl/srs/kzg17.srs
```

### Triggering code

```bash
ezkl create-evm-verifier
# looks for ~/.ezkl/srs/kzg17.srs — not ./kzg.srs
```

### Fixed code

```bash
ezkl create-evm-verifier \
  --srs-path kzg.srs \
  -S settings.json \
  --vk-path vk.key \
  --sol-code-path evm_deploy.sol
```

Requires prior `ezkl.setup(...)` so `vk.key` exists.

---

## Problem 18: `create-evm-verifier` — missing `solc`

**When:** solc not installed; network blocked.

**Error:**

```
[eth] svm error: error sending request for url (https://binaries.soliditylang.org/...)
```

### Triggering code

```bash
ezkl create-evm-verifier --srs-path kzg.srs -S settings.json --vk-path vk.key
# ezkl tries to auto-install solc via svm — fails without network
```

Install `solc` manually or retry with network access.

---

## Problem 19: Deploying contracts vs running `web3.js`

**When:** Treating `web3.js` like a contract to deploy.

### Triggering code

```bash
archon job -a test gen-witness   # wrong tool — Archon ≠ ezkl
brew install archon                # unrelated CLI
```

```javascript
// web3.js — calls verify on-chain; does not deploy itself
const proof = require('./proof.json');
const publicInputs = require('./input.json');  // may not match verifier calldata format

verifier.methods.verify(proof, publicInputs).call()
```

### Fixed workflow

1. Deploy `evm_deploy.sol` via Hardhat / Foundry / Remix
2. Set real `verifierAddress` in `web3.js`
3. Run `node web3.js` (may need ezkl EVM calldata encoding for proof/inputs)

---

## Problem 20: Slow `git push` after removing `node_modules`

**When:** `node_modules` was committed, then gitignored.

### Triggering code

```bash
git add .
git commit -m "add hardhat"   # accidentally included node_modules (5621 files)
# later: add node_modules to .gitignore and git rm --cached
git push   # still slow — history retains all blobs (~124MB .git)
```

`.gitignore` only prevents **future** commits; it does not remove blobs from history.

### Fix

Rewrite history (`git filter-repo --path node_modules --invert-paths`) or fresh repo.

---

## Quick reference


| Error / symptom                | Stage          | Triggering code (summary)              | Fix                                |
| ------------------------------ | -------------- | -------------------------------------- | ---------------------------------- |
| `KeyError: 'keras_tensor_N'`   | `tf2onnx`      | `Sequential([...]); from_keras(model)` | Functional API                     |
| `Reshape ToTypedTranslator`    | `gen_settings` | `Flatten()` + dynamic export           | `Reshape((21632,))` + static batch |
| Batch `unk__32`                | ONNX export    | `Input(shape=...)` only                | `input_signature`                  |
| `ModuleNotFoundError: tf2onnx` | Python         | `/opt/homebrew/bin/python3 model.py`   | `python model.py` in venv          |
| No TensorFlow on pip           | Python 3.14    | `python3.14 -m venv`                   | venv on 3.11/3.13                  |
| `command not found: ezkl`      | Install        | `pip install ezkl` then `ezkl`         | CLI install script                 |
| Installer stops at `aarch64`   | macOS CLI      | `install_ezkl_cli.sh | bash` (no tag)  | `bash -s v23.0.3`                  |
| `failed to load srs`           | `setup`        | `setup(..., "kzg.srs")` before SRS     | `get_srs` first                    |
| `get_srs` TypeError            | Python API     | `get_srs("settings.json", "kzg.srs")`  | `srs_path="kzg.srs"`               |
| `model.compiled` not found     | `gen_witness`  | `gen_witness()`                        | `model="network.ezkl"`             |
| `input.json` not found.        | `gen_witness`  | no file created                        | write flat JSON                    |
| deserialize error              | `gen_witness`  | `sample_input.tolist()` nested         | `.reshape(-1).tolist()`            |
| Slow runs                      | pipeline       | full `model.py` every time             | skip compile/setup                 |
| `kzg17.srs` not found          | EVM verifier   | `create-evm-verifier` bare             | `--srs-path kzg.srs`               |
| Slow git push                  | git            | committed `node_modules` once          | filter-repo / fresh repo           |


