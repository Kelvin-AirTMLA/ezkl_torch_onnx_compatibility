# import json
# import ezkl
import numpy as np
import tensorflow as tf
import tf2onnx

# toggle agents window: Cmd + Shft + M

# --- export Keras → ONNX ---
# Functional API Model - explicitly states the inputs and the outputs

# Sequential API model
# model = tf.keras.Sequential([
#     tf.keras.layers.Input(shape=(28, 28, 1)),
#     tf.keras.layers.Conv2D(32, (3, 3), activation="relu"),
#     tf.keras.layers.Flatten(),
#     tf.keras.layers.Dense(10, activation="softmax"),
# ])

# Functional API model
inputs = tf.keras.Input(shape=(28, 28, 1), batch_size=1)
x = tf.keras.layers.Conv2D(32, kernel_size=(3, 3), activation="relu")(inputs)
x = tf.keras.layers.Reshape((21632,))(x)
outputs = tf.keras.layers.Dense(10, activation="softmax")(x)

model = tf.keras.Model(inputs=inputs, outputs=outputs)

# input_signature = [tf.TensorSpec([1, 28, 28, 1], tf.float32, name="input")]

# defining the model
onnx_model, _ = tf2onnx.convert.from_keras(model)

with open("network.onnx", "wb") as f:
    f.write(onnx_model.SerializeToString())
    
print(inputs)
print(x)
print(outputs)

# # --- ezkl pipeline ---
# ezkl.gen_settings("network.onnx")
# ezkl.calibrate_settings("network.onnx", "settings.json", target="resources")
# ezkl.compile_circuit("network.onnx", "network.ezkl", "settings.json")

# if not __import__("os").path.exists("kzg.srs"):
#     ezkl.get_srs("settings.json", srs_path="kzg.srs")

# ezkl.setup("network.ezkl", "vk.key", "pk.key", "kzg.srs")

# # flat layout required by ezkl (nested arrays fail to deserialize)
# sample_input = np.random.default_rng(0).random((1, 28, 28, 1), dtype=np.float32)
# sample_output = model(sample_input).numpy()
# with open("input.json", "w") as f:
#     json.dump(
#         {
#             "input_data": [sample_input.reshape(-1).tolist()],
#             "output_data": [sample_output.reshape(-1).tolist()],
#         },
#         f,
#     )

# # witness generated 
# ezkl.gen_witness(
#     data="input.json",
#     model="network.ezkl",
#     output="witness.json",
# )

# # prove that the abstraction is complete and true
# # returns a proof key
# ezkl.prove(
#     witness="witness.json",
#     model="network.ezkl",
#     pk_path="pk.key",
#     proof_path="proof.json",
#     srs_path="kzg.srs",
# )

# # # returns a verify key
# ezkl.verify(
#     proof_path="proof.json",
#     settings_path="settings.json",
#     vk_path="vk.key",
#     srs_path="kzg.srs",
# )
