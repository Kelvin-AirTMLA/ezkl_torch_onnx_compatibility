import tf2onnx
import tensorflow as tf
# from tensorflow.keras import layers, models
import ezkl


inputs = tf.keras.Input(shape=(28, 28, 1))
x = tf.keras.layers.Conv2D(32, kernel_size=(3, 3), activation="relu")(inputs)
x = tf.keras.layers.Flatten()(x)
outputs = tf.keras.layers.Dense(10, activation="softmax")(x)

model = tf.keras.Model(inputs=inputs, outputs=outputs)

# this function requires A Functional API model and not a Sequential API model
onnx_model, _ = tf2onnx.convert.from_keras(model)
with open("network.onnx", "wb") as f:
    f.write(onnx_model.SerializeToString())


ezkl.gen_settings("network.onnx")