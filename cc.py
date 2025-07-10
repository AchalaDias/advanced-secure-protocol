import socket
import ssl
import json
import threading
import os
from datetime import datetime
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Configuration
SERVER_HOST = 'localhost'
SERVER_PORT = 5001
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
CERT_FILE = os.path.join(CURRENT_DIR, "server", "keys", "cert.pem")

# 🔐 Temporary static shared key (should match server key!)
AES_KEY = b"0123456789abcdef0123456789abcdef"  # 32 bytes for AES-256

# === CRYPTO UTILS ===
def encrypt_message(message: dict) -> dict:
    aesgcm = AESGCM(AES_KEY)
    iv = os.urandom(12)
    plaintext = json.dumps(message).encode()
    ciphertext = aesgcm.encrypt(iv, plaintext, None)
    return {
        "type": "secure",
        "ciphertext": b64encode(ciphertext).decode(),
        "iv": b64encode(iv).decode()
    }

def decrypt_message(encrypted_msg: dict) -> dict:
    aesgcm = AESGCM(AES_KEY)
    iv = b64decode(encrypted_msg["iv"])
    ciphertext = b64decode(encrypted_msg["ciphertext"])
    plaintext = aesgcm.decrypt(iv, ciphertext, None)
    return json.loads(plaintext.decode())

# === RECEIVE HANDLER ===
def recv_messages(sock):
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                break
            raw = json.loads(data.decode())

            if raw.get("type") == "secure":
                msg = decrypt_message(raw)
                print(f"\n[INCOMING] {msg}")
            else:
                print(f"\n[UNSECURE] {raw}")
        except Exception as e:
            print(f"[!] Error receiving: {e}")
            break

# === MAIN CLIENT ===
def start_client():
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # Insecure for testing

    with socket.create_connection((SERVER_HOST, SERVER_PORT)) as sock:
        with context.wrap_socket(sock, server_hostname=SERVER_HOST) as ssock:
            print("[+] Connected to secure server")

            choice = input("Register or Login? (r/l): ").lower()
            username = input("Username: ")
            password = input("Password: ")
            msg_type = "REGISTER" if choice == 'r' else "LOGIN"

            # Encrypt login or registration request
            msg = encrypt_message({
                "type": msg_type,
                "username": username,
                "password": password
            })
            ssock.sendall(json.dumps(msg).encode())

            # Decrypt login response
            resp = json.loads(ssock.recv(4096).decode())
            response = decrypt_message(resp)
            print("[SERVER]:", response)

            if response.get("status") != "OK":
                return

            my_uuid = response.get("uuid")

            # Start listener
            threading.Thread(target=recv_messages, args=(ssock,), daemon=True).start()

            # Request online users
            online_request = encrypt_message({ "type": "get_online_users" })
            ssock.sendall(json.dumps(online_request).encode())
            resp = json.loads(ssock.recv(4096).decode())
            online_users = decrypt_message(resp)
            print("[ONLINE USERS]:", online_users["online_users"])

            # Messaging loop
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

if __name__ == "__main__":
    start_client()
