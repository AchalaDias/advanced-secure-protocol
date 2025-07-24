import socket
import ssl
import json
import base64, os
import threading
from protocol.crypto import encrypt_message, decrypt_message
from protocol.session_manager import register_server_session
from db.db_config import DB_CONFIG
from protocol.logger import get_logger
from db.server_model import fetch_all_servers, save_server_users
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from protocol.crypto import generate_aes_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

logger = get_logger()

def connect_to_servers(server):
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        sock = socket.create_connection((server["hostname"], server["port"]))
        conn = context.wrap_socket(sock, server_hostname=server["hostname"])

        logger.info(f"[SERVER LINK] Connected to {server['name']} at {server['hostname']}:{server['port']}")

        aes_key = None

        if server["handshake_type"] == "auto":
            # === AUTO HANDSHAKE ===
            # Step 1: Receive public key from remote server
            key_data = conn.recv(2048)
            key_msg = json.loads(key_data.decode())

            if key_msg["type"] != "key_exchange":
                raise ValueError("Expected public key in key_exchange message")

            remote_public_key = serialization.load_pem_public_key(
                key_msg["public_key"].encode(),
                backend=default_backend()
            )

            # Step 2: Generate AES key and send it encrypted with their public key
            aes_key = generate_aes_key()
            encrypted_key = remote_public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            conn.sendall(json.dumps({
                "type": "aes_key",
                "key": base64.b64encode(encrypted_key).decode()
            }).encode())

        elif server["handshake_type"] == "manual":
            # === MANUAL HANDSHAKE ===
            remote_public_key_pem = server["public_key"]
            if not remote_public_key_pem:
                raise ValueError("Missing public key for manual handshake")

            remote_public_key = serialization.load_pem_public_key(
                remote_public_key_pem.encode(),
                backend=default_backend()
            )

            aes_key = generate_aes_key()
            encrypted_key = remote_public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            conn.sendall(json.dumps({
                "type": "aes_key",
                "key": base64.b64encode(encrypted_key).decode()
            }).encode())

        else:
            raise ValueError(f"Unknown handshake type: {server['handshake_type']}")

        # Step 3: Authenticate using credentials from DB
        auth_msg = {
            "type": "LOGIN",
            "username": server["username"],
            "password": server["password"]
        }
        
        conn.sendall(encrypt_message(auth_msg, aes_key))
        
        # Step 4: Await response
        response_data = conn.recv(4096)
        response = decrypt_message(response_data, aes_key)
        
        if response.get("status") != "OK":
            logger.error(f"[SERVER LINK] Authentication failed for {server['name']}")
            conn.close()
            return
        
        logger.info(f"[SERVER LINK] Authenticated with {server['name']}")
        # step 5: Register and start listener
        register_server_session(server["id"], server["name"], conn, aes_key)
        
        # Step 6: Request online users
        conn.sendall(encrypt_message({ "type": "online_user_request" }, aes_key))
        response = decrypt_message(conn.recv(4096), aes_key)
        online_users = response.get("online_users", [])
        save_server_users(server["id"], online_users)
        print(f"[SERVER ID {server['id']}] - ALL ONLINE USERS:", online_users)
        
        threading.Thread(target=listen_to_server, args=(server, conn, aes_key), daemon=True).start()

    except Exception as e:
        logger.error(f"[SERVER LINK] Failed to connect to {server['name']}: {e}")


def initiate_server_connections():
    servers = fetch_all_servers()
    for server in servers:
        connect_to_servers(server)

def listen_to_server(server, conn, aes_key):
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                logger.warning(f"[SERVER MESSAGE] No servers avaible to connect")
                break
            # TODO: Decrypt, parse, and handle inter-server messages
            logger.info(f"[SERVER MESSAGE] Received from {server['name']}: {data}")
    except Exception as e:
        logger.warning(f"[SERVER LINK] Lost connection to {server['name']}: {e}")
    finally:
        # TODO: clean up server session
        pass