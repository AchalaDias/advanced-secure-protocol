import base64
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Convert the AES key from hex string to raw bytes
aes_key_hex = "2ff3bd616905e79c437d3edac49529621cf1a4a50d7c7b2aa47ac1b3a5dede2d"
aes_key = bytes.fromhex(aes_key_hex)

# Your encrypted log data (from previous message)
log_entry = {"timestamp": "2025-07-11T07:28:34.977385Z", "sender_name": "achala", "sender_uuid": "e33dc7a3-35cf-4fa4-b16e-a6d96d6cdd3e", "payload": {"type": "secure", "ciphertext": "aAyCyWO1pk4/TFpTsI7bXVHwhGLBn8G6bkXo+VWpQz2gy/YI3GGYU0fa79/bbGWY2xOGwZfXRQNnBlYyKre2UbIPs5jT/V758nNGrvXaWoRpPEJeBSnfU+v3UGA1u+eeEJDK8RoRLJmcQj27h3Ct8WNhN4aoV+F3DG+v3vz1lZOjRzSUGk8qCTdzRwWmVMk+Vp6jBT3CPUVbzdEEFRn7hDrp3jW3o3Z7y5o=", "iv": "nQjokzvzsNEY1s34"}}

# Decode base64 IV and ciphertext
iv = base64.b64decode(log_entry["payload"]["iv"])
ciphertext = base64.b64decode(log_entry["payload"]["ciphertext"])

# Decrypt using AES-GCM
aesgcm = AESGCM(aes_key)

try:
    plaintext = aesgcm.decrypt(iv, ciphertext, None)
    message = json.loads(plaintext.decode())
    print("Decrypted message:")
    print(json.dumps(message, indent=4))
except Exception as e:
    print(f"Decryption failed: {e}")
