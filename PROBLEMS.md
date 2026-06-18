# Common problems — Keras → ONNX → ezkl

A log of errors encountered in this repo, what they mean, and why they happen.

Pipeline: **Keras → tf2onnx → `network.onnx` → `ezkl.gen_settings` → …**

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

You declare exactly which tensor enters and which tensor leaves. Keras and the traced graph agree on the graph boundary, so `model.output_names` and `tf2onnx`’s rename map line up.

### Comparison

| | Sequential | Functional |
|---|-----------|------------|
| Output definition | Implicit (last layer) | Explicit (`outputs=...`) |
| Internal tensor names | Auto-generated `keras_tensor_N` | Tied to declared graph |
| `from_keras` name lookup | Often breaks | Usually works |

### Why this got worse on TensorFlow 2.16+ / Keras 3

Known rough edge between **tf2onnx** and **modern Keras**, not invalid model math:

- Sequential models often lack clean `output_names` metadata (or get auto-generated ones)
- Keras 3 changed how models are traced and saved
- `tf2onnx` still assumes older naming conventions in places

Related issues: [tensorflow-onnx #2319](https://github.com/onnx/tensorflow-onnx/issues/2319), [#2348](https://github.com/onnx/tensorflow-onnx/issues/2348), [#2448](https://github.com/onnx/tensorflow-onnx/issues/2448).

### Fix

Use the **Functional API** when exporting to ONNX. See `model.py` in this repo.

---

## Problem 2: `Reshape ToTypedTranslator` — why Flatten is the problem

**When:** `ezkl.gen_settings("network.onnx")` after a successful ONNX export.

**Error:**

```
RuntimeError: Failed to generate settings: [graph] [tract] Translating node #17 
"functional_1/flatten_1/Reshape" Reshape ToTypedTranslator
```

### What it means

During `gen_settings`, ezkl uses **tract** to read the ONNX graph and infer **concrete tensor shapes** for every node. It fails on the **Reshape** node produced by Keras **`Flatten()`**.

`ToTypedTranslator` is the step where tract turns inferred shapes into fully typed, fixed shapes. **Reshape** requires the target shape to be known at compile time. Tract could not determine it, so settings generation stops.

This is **not** “ezkl doesn’t support Flatten.” The ONNX file is valid for normal inference — it is **not static enough** for ezkl’s circuit builder.

### Why Flatten is the problem

Keras `Flatten()` is exported by tf2onnx as a **dynamic Reshape**, not a simple constant reshape.

In `network.onnx`, Flatten becomes a subgraph like:

```
Shape → Slice → Concat (with -1) → Reshape
```

That means: “compute the output shape from the **actual input tensor** at runtime, then reshape.” This works in ONNX Runtime.

**ezkl is different.** It builds a zero-knowledge circuit where dimensions must be **fixed before proving**. Tract cannot compile a Reshape whose target shape comes from a runtime `Shape` op when dimensions upstream are still symbolic.

### Why Conv2D didn’t fail first

Convolution and ReLU shapes are easier for tract to infer even with a symbolic batch dimension. **Reshape with a runtime-computed shape tensor** is where static analysis breaks. In a small CNN, Flatten is often the first op that forces dynamic shape logic into the graph.

---

## Problem 3: The root cause — dynamic batch size

The dynamic Flatten/Reshape issue is driven by a **dynamic batch dimension** on the model input.

### What the ONNX file shows

Inspecting `network.onnx` exported from:

```python
inputs = tf.keras.Input(shape=(28, 28, 1))  # batch size not fixed
```

| Dimension | Value |
|-----------|--------|
| Batch | **dynamic** (`unk__32`) |
| Height | 28 |
| Width | 28 |
| Channels | 1 |

Default Keras `Input(shape=...)` leaves batch as **None** — flexible for training, but problematic for ezkl.

### How dynamic batch breaks Flatten

1. Batch is unknown at export time → ONNX records it as a symbolic dim (`unk__32`).
2. Flatten must produce `[batch, flattened_size]`. With unknown batch, tf2onnx emits **Shape / Slice / Concat** to build the reshape target at runtime.
3. tract hits that Reshape during `gen_settings` and cannot resolve the target shape → **`ToTypedTranslator` fails**.

Same class of issue as dynamic `flatten` / `reshape` in PyTorch ONNX export: valid for inference, too dynamic for ezkl.

### What ezkl needs vs normal inference

| Normal inference (ONNX Runtime) | ezkl / tract |
|--------------------------------|--------------|
| Batch can be dynamic | Shapes should be **fixed** |
| Reshape target can come from `Shape` ops | Reshape target must be **known at compile time** |
| Run with whatever batch you pass | Build a circuit for **one specific graph** |

ZK proving requires a fixed computation graph. Dynamic axes are a fundamental mismatch, not a minor config issue.

### How to confirm

```bash
python -c "
import onnx
m = onnx.load('network.onnx')
d = m.graph.input[0].type.tensor_type.shape.dim[0]
print('batch dim_value:', d.dim_value, 'dim_param:', repr(d.dim_param))
"
```

If `dim_param` is something like `'unk__32'` and `dim_value` is `0`, batch is dynamic — this matches the failure mode above.

### Fix directions

1. **Fixed batch at export** — e.g. `batch_size=1` on `Input`, or pass an explicit `input_signature` to `from_keras` so tf2onnx does not emit a symbolic batch.
2. **Replace `Flatten()` with a fixed `Reshape`** — after Conv2D `(3,3)` on `28×28`, spatial size is `26×26×32 = 21632`; a constant reshape avoids the Shape/Slice/Concat chain.
3. **Post-process ONNX** — set input batch `dim_value = 1` and clear `dim_param`. Sometimes enough; often still need (1) or (2) if the Flatten subgraph stays dynamic.

---

## Quick reference

| Error | Stage | Root cause | Fix |
|-------|-------|------------|-----|
| `KeyError: 'keras_tensor_N'` | `tf2onnx.from_keras` | Sequential model; output name mismatch in trace | Use Functional API |
| `Reshape ToTypedTranslator` | `ezkl.gen_settings` | Flatten exported as dynamic Reshape | Fix static shapes (see Problem 3) |
| Dynamic batch (`unk__32`) | ONNX export | Batch not fixed at export time | `batch_size=1`, `input_signature`, or ONNX post-process |
