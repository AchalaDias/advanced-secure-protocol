import socket
import ssl
import json
import threading
import os, base64
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SERVER_HOST = 'localhost'
SERVER_PORT = 5001
aes_key = None
my_uuid = None
my_name = None
chat_uuid = None
chat_name = None
chat_ready = threading.Event()  # sync flag for first message or uuid input

def encrypt_message(message_dict: dict) -> bytes:
    global aes_key
    aesgcm = AESGCM(aes_key)
    iv = os.urandom(12)
    plaintext = json.dumps(message_dict).encode('utf-8')
    ciphertext = aesgcm.encrypt(iv, plaintext, None)
    return iv + ciphertext

def decrypt_message(encrypted_bytes: bytes) -> dict:
    global aes_key
    aesgcm = AESGCM(aes_key)
    iv = encrypted_bytes[:12]
    ciphertext = encrypted_bytes[12:]
    plaintext = aesgcm.decrypt(iv, ciphertext, None)
    return json.loads(plaintext.decode('utf-8'))

def recv_messages(sock):
    global chat_uuid, chat_name
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                break
            msg = decrypt_message(data)
            if msg.get("type") == "message":
                sender_id = msg.get("from_id") or msg.get("from")
                sender_name = msg.get("from") or "Unknown"
                payload = msg.get("payload", "")

                # Auto-bind chat target if not already set
                if chat_uuid is None:
                    chat_uuid = sender_id
                    chat_name = sender_name
                    print(f"\n✅ Chat locked to {chat_name} ({chat_uuid})")
                    print(f"💬 Chatting with {chat_name}. Type your messages below:\n")
                    chat_ready.set()

                print(f"{sender_name}: {payload}")
            elif msg.get("type") == "user_status" and msg.get("status") == "online":
                # Optional: show who's online
                print(f"\n🔔 {msg.get('name')} - {msg.get('user_id')}  is online.")
        except Exception as e:
            print(f"[!] Error receiving: {e}")
            break

def start_client():
    global aes_key, my_uuid, my_name, chat_uuid, chat_name
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((SERVER_HOST, SERVER_PORT)) as sock:
        with context.wrap_socket(sock, server_hostname=SERVER_HOST) as ssock:
            print("🔐 Connected to secure server")

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

            # Step 3: Authenticate
            choice = input("Register or Login? (r/l): ").lower()
            username = input("Username: ")
            password = input("Password: ")
            msg_type = "REGISTER" if choice.lower() == 'r' else "LOGIN"

            auth_msg = {
                "type": msg_type,
                "username": username,
                "password": password
            }
            ssock.sendall(encrypt_message(auth_msg))
            response = decrypt_message(ssock.recv(4096))

            print("[SERVER]:", response)
            if response.get("status") != "OK":
                return

            my_uuid = response.get("uuid")
            my_name = response.get("username")

            # Step 4: Request online users
            ssock.sendall(encrypt_message({ "type": "online_user_request" }))
            response = decrypt_message(ssock.recv(4096))
            print("[SERVER] - ALL ONLINE USERS:", response['online_users'])

            # Step 5: Start receiver thread
            threading.Thread(target=recv_messages, args=(ssock,), daemon=True).start()

            # Step 6: Optional manual target if not auto-bound
            if not chat_ready.wait(timeout=1):  # wait max 3 sec for incoming message
                chat_uuid = input("\nEnter recipient user UUID: ")
                chat_name = chat_uuid
                print(f"💬 Chatting with {chat_name}. Type your messages below:\n")
                chat_ready.set()

            # Step 7: Send loop
            while True:
                try:
                    text = input("> ")
                    message = {
                        "type": "message",
                        "from": my_uuid,
                        "to": chat_uuid,
                        "to_type": "user",
                        "payload": text,
                        "payload_type": "text",
                        "timestamp": datetime.utcnow().isoformat() + "Z"
                    }
                    ssock.sendall(encrypt_message(message))
                except KeyboardInterrupt:
                    print("\n👋 Exiting chat.")
                    break

if __name__ == "__main__":
    start_client()
