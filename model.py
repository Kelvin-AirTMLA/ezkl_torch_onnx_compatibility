import json

import ezkl
import numpy as np
import tensorflow as tf
import tf2onnx

# --- export Keras → ONNX ---
inputs = tf.keras.Input(shape=(28, 28, 1), batch_size=1)
x = tf.keras.layers.Conv2D(32, kernel_size=(3, 3), activation="relu")(inputs)
x = tf.keras.layers.Reshape((21632,))(x)
outputs = tf.keras.layers.Dense(10, activation="softmax")(x)

model = tf.keras.Model(inputs=inputs, outputs=outputs)

input_signature = [tf.TensorSpec([1, 28, 28, 1], tf.float32, name="input")]
onnx_model, _ = tf2onnx.convert.from_keras(model, input_signature=input_signature)
with open("network.onnx", "wb") as f:
    f.write(onnx_model.SerializeToString())

# --- ezkl pipeline ---
ezkl.gen_settings("network.onnx")
ezkl.compile_circuit("network.onnx", "network.ezkl", "settings.json")

if not __import__("os").path.exists("kzg.srs"):
    ezkl.get_srs("settings.json", srs_path="kzg.srs")

ezkl.setup("network.ezkl", "vk.key", "pk.key", "kzg.srs")

# flat layout required by ezkl (nested arrays fail to deserialize)
sample_input = np.random.default_rng(0).random((1, 28, 28, 1), dtype=np.float32)
sample_output = model(sample_input).numpy()
with open("input.json", "w") as f:
    json.dump(
        {
            "input_data": [sample_input.reshape(-1).tolist()],
            "output_data": [sample_output.reshape(-1).tolist()],
        },
        f,
    )

ezkl.gen_witness(
    data="input.json",
    model="network.ezkl",
    output="witness.json",
)
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
