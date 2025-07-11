from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os, base64, json

# Generate RSA key pair
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

# Serialize public key to PEM
def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

# Deserialize public key from PEM
def load_public_key(pem_str):
    return serialization.load_pem_public_key(pem_str.encode())

# Decrypt AES key using RSA private key
def decrypt_aes_key(encrypted_key, private_key):
    return private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# AESGCM encrypt/decrypt (session key passed externally)
def encrypt_message(full_message: dict, aes_key: bytes) -> dict:
    aesgcm = AESGCM(aes_key)
    iv = os.urandom(12)
    plaintext = json.dumps(full_message).encode()
    ciphertext = aesgcm.encrypt(iv, plaintext, None)
    return {
        "type": "secure",
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "iv": base64.b64encode(iv).decode()
    }
# AESGCM decrypt (session key passed externally)
def decrypt_message(encrypted_msg: dict, aes_key: bytes) -> dict:
    aesgcm = AESGCM(aes_key)
    iv = base64.b64decode(encrypted_msg["iv"])
    ciphertext = base64.b64decode(encrypted_msg["ciphertext"])
    plaintext = aesgcm.decrypt(iv, ciphertext, None)
    return json.loads(plaintext.decode())
