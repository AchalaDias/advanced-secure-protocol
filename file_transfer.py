import socket
import ssl
import json
import os
import base64
import threading
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SERVER_HOST = 'localhost'
SERVER_PORT = 5001
aes_key = None

# CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
# CERT_FILE = os.path.join(CURRENT_DIR, "server", "keys", "cert.pem")

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

            if msg.get("payload_type") == "file":
                filename = f"received_{datetime.utcnow().strftime('%H%M%S')}.bin"
                with open(filename, "wb") as f:
                    f.write(base64.b64decode(msg["payload"]))
                print(f"\n📁 File received and saved as {filename}")
            else:
                print(f"\n[INCOMING] {msg}")
        except Exception as e:
            print(f"[!] Error receiving: {e}")

def start_client():
    global aes_key
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((SERVER_HOST, SERVER_PORT)) as sock:
        with context.wrap_socket(sock, server_hostname=SERVER_HOST) as ssock:
            print("[+] Connected to server.")

            # 1. RSA Public Key Exchange
            key_msg = json.loads(ssock.recv(2048).decode())
            server_pub_key = serialization.load_pem_public_key(key_msg["public_key"].encode())

            aes_key = os.urandom(32)
            encrypted_key = server_pub_key.encrypt(
                aes_key,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            key_payload = {
                "type": "aes_key",
                "key": base64.b64encode(encrypted_key).decode()
            }
            ssock.sendall(json.dumps(key_payload).encode())

            # 2. Login or Register
            choice = input("Register or Login? (r/l): ").lower()
            username = input("Username: ")
            password = input("Password: ")
            msg_type = "REGISTER" if choice == 'r' else "LOGIN"

            encrypted = encrypt_message({
                "type": msg_type,
                "username": username,
                "password": password
            })
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

            uuid = response.get("uuid")

            # 3. Start receiving thread
            threading.Thread(target=recv_messages, args=(ssock,), daemon=True).start()

            # 4. File Sending Loop
            while True:
                to_type = input("\nSend to (user/group): ").strip().lower()
                to_id = input("Enter UUID (user) or Group ID (group): ").strip()
                file_path = input("Path to file: ").strip()

                if not os.path.exists(file_path):
                    print("[!] File not found.")
                    continue

                file_size = os.path.getsize(file_path)
                if file_size > 10 * 1024 * 1024:
                    print("[!] File exceeds 10MB limit. Aborted.")
                    continue

                with open(file_path, "rb") as f:
                    encoded = base64.b64encode(f.read()).decode()

                msg = {
                    "type": "message_file" if to_type == "user" else "group_file",
                    "from": uuid,
                    "to": to_id,
                    "to_type": to_type,
                    "payload": encoded,
                    "payload_type": "file",
                    "timestamp": datetime.utcnow().isoformat() + "Z"
                }

                ssock.sendall(json.dumps(encrypt_message(msg)).encode())
                print("File sent.")

def encrypt_message(message_dict):
    global aes_key
    aesgcm = AESGCM(aes_key)
    iv = os.urandom(12)
    ciphertext = aesgcm.encrypt(iv, json.dumps(message_dict).encode(), None)
    return {
        "type": "secure",
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "iv": base64.b64encode(iv).decode()
    }

def decrypt_message(encrypted_msg):
    global aes_key
    aesgcm = AESGCM(aes_key)
    iv = base64.b64decode(encrypted_msg["iv"])
    ciphertext = base64.b64decode(encrypted_msg["ciphertext"])
    plaintext = aesgcm.decrypt(iv, ciphertext, None)
    return json.loads(plaintext.decode())

if __name__ == "__main__":
    start_client()
