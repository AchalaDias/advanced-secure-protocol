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
            msg = decrypt_message(data)

            # Pretty print only group name or user + payload
            if msg.get("type") == "group_message" and msg.get("to_type") == "group":
                group = msg.get("to", "GROUP")
                sender = msg.get("from", "User")
                payload = msg.get("payload", "")
                print(f"\n[{group}] {sender}: {payload}")
            else:
                print(f"\n[INCOMING] {msg}")
        except Exception as e:
            print(f"Error receiving: {e}")

def start_client():
    global aes_key
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((SERVER_HOST, SERVER_PORT)) as sock:
        with context.wrap_socket(sock, server_hostname=SERVER_HOST) as ssock:
            print("Connected to secure server")

            # Step 1: Receive RSA public key
            key_data = ssock.recv(2048)
            key_msg = json.loads(key_data.decode())
            server_pub_key = serialization.load_pem_public_key(key_msg["public_key"].encode())

            # Step 2: Generate and send AES key
            aes_key = os.urandom(32)
            encrypted_key = server_pub_key.encrypt(
                aes_key,
                padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            ssock.sendall(json.dumps({
                "type": "aes_key",
                "key": base64.b64encode(encrypted_key).decode()
            }).encode())

            # Step 3: Register or login
            choice = input("Register or Login? (r/l): ").lower()
            username = input("Username: ")
            password = input("Password: ")
            msg_type = "REGISTER" if choice == 'r' else "LOGIN"

            encrypted = encrypt_message({
                "type": msg_type,
                "username": username,
                "password": password
            })
            ssock.sendall(encrypted)
            response = decrypt_message(ssock.recv(4096))

            print("[SERVER]:", response)
            if response.get("status") != "OK":
                return
            
            # Step 4: Request online users
            encrypted = encrypt_message({ "type": "online_user_request" })
            ssock.sendall(encrypted)
            response = decrypt_message(ssock.recv(4096))
            print("[SERVER] - ALL ONLINE USERS:", response['online_users'])
            my_uuid = response.get("uuid")

            # Start listener thread
            threading.Thread(target=recv_messages, args=(ssock,), daemon=True).start()

            # Main group test loop
            while True:
                print("\n1. Create Group")
                print("2. List My Groups")
                print("3. Add User to Group")
                print("4. Send Message to Group")
                choice = input("Select option: ")

                if choice == "1":
                    gname = input("Group Name: ")
                    msg = encrypt_message({
                        "type": "create_group",
                        "group_name": gname
                    })
                    ssock.sendall(msg)

                elif choice == "2":
                    msg = encrypt_message({ "type": "list_my_groups" })
                    ssock.sendall(msg)
                    
                elif choice == "3":
                    gid = input("Group ID: ")
                    user_to_add = input("User ID to add: ")
                    msg = encrypt_message({
                        "type": "add_user_to_group",
                        "group_id": gid,
                        "user_id": user_to_add
                    })
                    ssock.sendall(msg)

                elif choice == "4":
                    gid = input("Group ID to send to: ")
                    text = input("Message: ")
                    message = {
                        "type": "group_message",
                        "from": my_uuid,
                        "to": gid,
                        "to_type": "group",
                        "payload": text,
                        "payload_type": "text",
                        "timestamp": datetime.utcnow().isoformat() + "Z"
                    }
                    encrypted = encrypt_message(message)
                    ssock.sendall(encrypted)

# Encrypt message (returns raw binary: iv + ciphertext)
def encrypt_message(message_dict):
    global aes_key
    aesgcm = AESGCM(aes_key)
    iv = os.urandom(12)
    plaintext = json.dumps(message_dict).encode('utf-8')
    ciphertext = aesgcm.encrypt(iv, plaintext, None)
    return iv + ciphertext  # return raw binary

# Decrypt incoming binary message
def decrypt_message(data):
    global aes_key
    aesgcm = AESGCM(aes_key)
    iv = data[:12]
    ciphertext = data[12:]
    plaintext = aesgcm.decrypt(iv, ciphertext, None)
    return json.loads(plaintext.decode('utf-8'))

if __name__ == "__main__":
    start_client()
