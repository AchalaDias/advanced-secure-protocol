import socket
import ssl
import json
import threading
import os
import base64
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SERVER_HOST = 'localhost'
SERVER_PORT = 5001
aes_key = None

def recv_messages(sock):
    global aes_key
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                break
            msg = json.loads(data.decode())

            if msg.get("type") == "secure":
                aesgcm = AESGCM(aes_key)
                iv = base64.b64decode(msg["iv"])
                ciphertext = base64.b64decode(msg["ciphertext"])
                plaintext = aesgcm.decrypt(iv, ciphertext, None)
                msg = json.loads(plaintext.decode())

            print(f"\n[INCOMING] {msg}")
        except Exception as e:
            print(f"[!] Error receiving: {e}")
            # break

def start_client():
    global aes_key
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((SERVER_HOST, SERVER_PORT)) as sock:
        with context.wrap_socket(sock, server_hostname=SERVER_HOST) as ssock:
            print("Connected to secure server")

            # Step 1: Receive server's RSA public key
            key_data = ssock.recv(2048)
            key_msg = json.loads(key_data.decode())
            server_pub_key_pem = key_msg["public_key"]
            server_pub_key = serialization.load_pem_public_key(server_pub_key_pem.encode())

            # Step 2: Generate AES key and send it encrypted
            aes_key = os.urandom(32)
            encrypted_key = server_pub_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            key_payload = {
                "type": "aes_key",
                "key": base64.b64encode(encrypted_key).decode()
            }
            ssock.sendall(json.dumps(key_payload).encode())

            # Step 3: Authenticate/Register
            choice = input("Register or Login? (r/l): ").lower()
            username = input("Username: ")
            password = input("Password: ")

            msg_type = "REGISTER" if choice == 'r' else "LOGIN"
            msg = {
                "type": msg_type,
                "username": username,
                "password": password
            }

            encrypted = encrypt_message(msg)
            ssock.sendall(json.dumps(encrypted).encode())
            response = json.loads(ssock.recv(4096).decode())
            if response.get("type") == "secure":
                response = decrypt_message(response)

            print("[SERVER]:", response)
            if response.get("status") != "OK":
                return

            # Step 4: Request online users
            encrypted = encrypt_message({ "type": "get_online_users" })
            ssock.sendall(json.dumps(encrypted).encode())
            response = json.loads(ssock.recv(4096).decode())
            if response.get("type") == "secure":
                response = decrypt_message(response)
            print("[SERVER] - ALL ONLINE USERS:", response['online_users'])
            my_uuid = response.get("uuid")

            # Step 5: Start receiving thread
            threading.Thread(target=recv_messages, args=(ssock,), daemon=True).start()

            while True:
                to_uuid = input("\nSend to user UUID: ")
                text = input("Enter message: ")
                message = {
                    "type": "message",
                    "from": my_uuid,
                    "to": to_uuid,
                    "to_type": "user",
                    "payload": text,
                    "payload_type": "text",
                    "timestamp": datetime.utcnow().isoformat() + "Z"
                }
                encrypted = encrypt_message(message)
                ssock.sendall(json.dumps(encrypted).encode())

# Message Encryption before sending to server
def encrypt_message(message_dict):
    global aes_key
    aesgcm = AESGCM(aes_key)
    iv = os.urandom(12)
    plaintext = json.dumps(message_dict).encode()
    ciphertext = aesgcm.encrypt(iv, plaintext, None)
    return {
        "type": "secure",
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "iv": base64.b64encode(iv).decode()
    }
# Decrypt incoming message
def decrypt_message(encrypted_msg):
    global aes_key
    aesgcm = AESGCM(aes_key)
    iv = base64.b64decode(encrypted_msg["iv"])
    ciphertext = base64.b64decode(encrypted_msg["ciphertext"])
    plaintext = aesgcm.decrypt(iv, ciphertext, None)
    return json.loads(plaintext.decode())

if __name__ == "__main__":
    start_client()
