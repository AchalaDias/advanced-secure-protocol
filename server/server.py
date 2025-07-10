import socket
import ssl
import threading
import os
from db.db_init import init_db
from protocol.connection_handler import handle_client_connection

HOST = '0.0.0.0'
PORT = 5001

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
CERT_FILE = os.path.join(CURRENT_DIR, "keys", "cert.pem")
KEY_FILE = os.path.join(CURRENT_DIR, "keys", "key.pem")

def start_server():
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((HOST, PORT))
        sock.listen(5)
        print(f"[SERVER] TLS Chat Server running on {HOST}:{PORT}")

        while True:
            client_sock, addr = sock.accept()
            connstream = context.wrap_socket(client_sock, server_side=True)
            threading.Thread(target=handle_client_connection, args=(connstream, addr)).start()

if __name__ == "__main__":
    init_db()
    start_server()
