import socket
import ssl
import json
import threading
import os
from datetime import datetime

SERVER_HOST = 'localhost'
SERVER_PORT = 5001

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
CERT_FILE = os.path.join(CURRENT_DIR, "server", "keys", "cert.pem")

def recv_messages(sock):
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                break
            msg = json.loads(data.decode())
            print(f"\n[INCOMING] {msg}")
        except Exception as e:
            print(f"[!] Error receiving: {e}")
            break

def start_client():
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # Skip verification for test

    with socket.create_connection((SERVER_HOST, SERVER_PORT)) as sock:
        with context.wrap_socket(sock, server_hostname=SERVER_HOST) as ssock:
            print("[+] Connected to secure server")

            choice = input("Register or Login? (r/l): ").lower()
            username = input("Username: ")
            password = input("Password: ")

            msg_type = "REGISTER" if choice == 'r' else "LOGIN"
            msg = {
                "type": msg_type,
                "username": username,
                "password": password
            }

            ssock.sendall(json.dumps(msg).encode())
            response = json.loads(ssock.recv(4096).decode())
            print("[SERVER]:", response)

            if response.get("status") != "OK":
                return
            
            # list all online users
            ssock.sendall(json.dumps({ "type": "get_online_users" }).encode())
            response = json.loads(ssock.recv(4096).decode())
            print("[SERVER] - ALL ONLINE USERS:", response['online_users'])
            
            my_uuid = response.get("uuid")

            # Start receiver thread
            threading.Thread(target=recv_messages, args=(ssock,), daemon=True).start()

            # Message loop
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
                ssock.sendall(json.dumps(message).encode())

if __name__ == "__main__":
    start_client()
