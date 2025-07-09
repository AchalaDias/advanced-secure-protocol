# server/server.py

import socket
import ssl
import threading
import os
from protocol.handler import process_message
from db.db_init import init_db

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__)) 
CERT_FILE = os.path.join(CURRENT_DIR, "keys", "cert.pem")
KEY_FILE = os.path.join(CURRENT_DIR, "keys", "key.pem")

print(CERT_FILE, KEY_FILE)

def handle_client(connstream, addr):
    print(f"[+] Connection from {addr}")
    try:
        data = connstream.recv(2048).decode()
        if not data:
            return
        response = process_message(data)
        connstream.sendall(response.encode())
    except Exception as e:
        print(f"[!] Exception: {e}")
        connstream.sendall(b'{"status": "ERROR", "message": "Server exception"}')
    finally:
        connstream.close()

def start_server(host='0.0.0.0', port=5001):
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, port))
        sock.listen(5)
        print(f"[SERVER] TLS Chat Server running on {host}:{port}")

        while True:
            client_sock, addr = sock.accept()
            connstream = context.wrap_socket(client_sock, server_side=True)
            threading.Thread(target=handle_client, args=(connstream, addr)).start()

if __name__ == "__main__":
    init_db()
    start_server()
