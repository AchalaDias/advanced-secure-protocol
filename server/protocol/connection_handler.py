import json, base64
from protocol.logger import get_logger
from protocol.session_manager import register_session, remove_session, get_session_by_socket
from db.group_model import get_groups_by_user
from protocol.crypto import (
    generate_rsa_key_pair,
    serialize_public_key,
    decrypt_aes_key,
    encrypt_message
)
from protocol.handler import ( 
    user_authentication, 
    extract_incoming_message, 
    user_to_user_message, 
    user_to_group_message, 
    get_online_users, 
    create_group_message,
    add_user_to_message_group,
    broadcast_online_users,
    send_files
)

logger = get_logger()

def handle_client_connection(connstream, addr):
    logger.info(f"[+] Connection from {addr}")
    user_uuid = None
    
    # Generate RSA keys per session
    private_key, public_key = generate_rsa_key_pair()

    # Step 1: Send public key to client
    try:
        public_key_pem = serialize_public_key(public_key)
        connstream.sendall(json.dumps({
            "type": "key_exchange",
            "public_key": public_key_pem
        }).encode())
    except Exception as e:
        logger.error(f"Failed to send public key: {e}")
        return

    # Step 2: Receive encrypted AES session key
    try:
        key_data = connstream.recv(2048)
        key_msg = json.loads(key_data.decode())
        if key_msg["type"] != "aes_key":
            raise ValueError("Expected AES key payload")

        encrypted_key = base64.b64decode(key_msg["key"])
        aes_key = decrypt_aes_key(encrypted_key, private_key)
    except Exception as e:
        logger.error(f"Failed to receive AES key: {e}")
        return

    try:
        # Read incoming data stream
        data = connstream.recv(2048).decode()
        if not data:
            return
        # Extract Json data from incoming message
        msg = extract_incoming_message(data, connstream, aes_key)     
    
        # User Authentication
        response_data, user_uuid, username = user_authentication(msg)
        if user_uuid:
            register_session(user_uuid, username, connstream, aes_key)
            logger.info(f"User {username} ({user_uuid}) is online")
            
        connstream.sendall(json.dumps(response_data).encode())

        # Loop for messages or commands
        while True:
            data = connstream.recv(4 * 1024).decode()
            if not data:
                break
            
            msg = extract_incoming_message(data, connstream, aes_key)
                
            try:
                # Validate session
                user_uuid, session = get_session_by_socket(connstream)
                if not session:
                    logger.warning(f"Unauthorized connection {user_uuid}")
                    connstream.sendall(json.dumps({
                        "type": "error",
                        "message": "Unauthorized connection"
                    }).encode())
                    break
                
                # Inform other users or peer servers about the new user
                broadcast_online_users(user_uuid, session)
                # ====================== User to User Messaging =====================
                # Passing message between users (Private messages)
                if msg.get("type") == "message" and msg.get("to_type") == "user":
                    user_to_user_message(msg, connstream, user_uuid, session)
                
                #  Broadcast Message to Group Members 
                elif msg.get("type") == "message" and msg.get("to_type") == "group":
                    user_to_group_message(msg, user_uuid, session)
                
                # Fetch online users list
                elif msg.get("type") == "get_online_users":
                    get_online_users(user_uuid, session, connstream)
                # ====================================================================

                # ======================= Group Messaging ============================     
                # Create message groups
                elif msg.get("type") == "create_group":
                    create_group_message(msg, user_uuid, connstream, aes_key)
                    
                # List all users groups 
                elif msg.get("type") == "list_my_groups":
                    groups = get_groups_by_user(user_uuid)
                    response = {
                        "type": "list_my_groups",
                        "groups": groups
                    }
                    connstream.sendall(json.dumps(encrypt_message(response, aes_key)).encode())    
                       
                # Adding user to group 
                elif msg.get("type") == "add_user_to_group":
                    add_user_to_message_group(msg, connstream, aes_key)        
                # ===========================================================================

                # ======================== File Transfering =================================           
                elif msg.get("type") in ["message_file", "group_file"]:
                    send_files(msg, user_uuid, session, connstream, aes_key)
                # ===========================================================================      
                else:
                    logger.error(f"Unknown message type")
                    connstream.sendall(json.dumps({
                        "type": "error",
                        "message": "Unknown message type"
                    }).encode())
            except Exception as msg_err:
                logger.error(f"Failed to process message: {msg_err}")
                connstream.sendall(json.dumps({
                    "type": "error",
                    "message": "Failed to parse message"
                }).encode())

    except Exception as e:
        logger.error(f"Exception with {addr}: {e}")
    finally:
        if user_uuid:
            remove_session(user_uuid)
            logger.info(f"User {username} ({user_uuid}) is offline")
        connstream.close()
