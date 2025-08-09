## Group Name & Members
# - Group Name: Group Project 8
# - Anthonan Hettige Achala Tharaka Dias (a1933508)
# - Sanjida Amrin (a1934493)
# - Zahin Rydha (a1938252)

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os, json, base64
from datetime import datetime

# Generate AES key
def generate_aes_key():
    return AESGCM.generate_key(bit_length=256)

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
def encrypt_message(full_message: dict, aes_key: bytes) -> bytes:
    aesgcm = AESGCM(aes_key)
    iv = os.urandom(12)
    plaintext = json.dumps(full_message).encode('utf-8')
    ciphertext = aesgcm.encrypt(iv, plaintext, None)
    return iv + ciphertext  # concatenate nonce and ciphertext

# AESGCM decrypt (session key passed externally)
def decrypt_message(encrypted_data: bytes, aes_key: bytes) -> dict:
    aesgcm = AESGCM(aes_key)
    iv = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    plaintext = aesgcm.decrypt(iv, ciphertext, None)
    return json.loads(plaintext.decode('utf-8'))

# Transaction logging
def log_encrypted_payload(sender_name: str, sender_uuid: str,payload: dict):
    with open(".msglog", "a") as f:
        f.write(json.dumps({
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "sender_name": sender_name,
            "sender_uuid": sender_uuid,
            "payload": base64.b64encode(payload).decode()
        }) + "\n")