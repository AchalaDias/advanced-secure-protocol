## Group Name & Members
# - Group Name: Group Project 8
# - Anthonan Hettige Achala Tharaka Dias (a1933508)
# - Sanjida Amrin (a1934493)
# - Zahin Rydha (a1938252)

import socket
import ssl
import threading
import os
from db.db_init import init_db
from protocol.logger import get_logger
from protocol.connection_handler import handle_client_connection
from protocol.server_link import initiate_server_connections

logger = get_logger()
HOST = os.getenv("SERVER_HOST", "0.0.0.0")
PORT = int(os.getenv("SERVER_PORT", 5001))

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
CERT_FILE = os.path.join(CURRENT_DIR, "keys", "cert.pem")
KEY_FILE = os.path.join(CURRENT_DIR, "keys", "key.pem")

def start_server():
    """
    Starts a TLS-secured chat server that listens for client connections.

    Behavior:
        - Creates an SSL context and loads the server's certificate and private key.
        - Binds to the specified HOST and PORT.
        - Listens for incoming connections and wraps each one with TLS.
        - Spawns a new thread for each client using `handle_client_connection`.
    """
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((HOST, PORT))
        sock.listen(5)
        logger.info(f"[SERVER] TLS Chat Server running on {HOST}:{PORT}")

        while True:
            client_sock, addr = sock.accept()
            connstream = context.wrap_socket(client_sock, server_side=True)
            threading.Thread(target=handle_client_connection, args=(connstream, addr)).start()

if __name__ == "__main__":
    init_db()
    initiate_server_connections()  # Step 2: Start server-to-server sessions
    start_server()
