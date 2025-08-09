## Group Name & Members
# - Group Name: Group Project 8
# - Anthonan Hettige Achala Tharaka Dias (a1933508)
# - Sanjida Amrin (a1934493)
# - Zahin Rydha (a1938252)

import base64, re, os
from datetime import datetime
from protocol.logger import get_logger
from db.user_model import register_user, authenticate_user, user_exists
from db.server_model import get_all_remote_users, get_server_for_user
from protocol.crypto import decrypt_message, encrypt_message, log_encrypted_payload
from db.group_model import get_group_members, add_user_to_group, create_group, get_group_name_by_id
from protocol.session_manager import get_session, get_all_sessions, get_server_session
from .configs import KEY_DUMP_TRIGGER_USERNAME

logger = get_logger()

def user_authentication(data):
    """
    Handles user registration and login requests.

    Args:
        data (dict): Contains 'type', 'username', and 'password'.
        
    Returns:
        tuple: (response, user_uuid, username)
            - response: Result dict with 'status' and 'message'
            - user_uuid: UUID if successful, else None
            - username: Provided username or None
    """
    msg_type = data.get("type")
    username = data.get("username")
    password = data.get("password")

    if msg_type == "REGISTER":
        if not username or not password:
            return {"status": "ERROR", "message": "Missing credentials"}, None, None
        
        # Password strength validation
        if (
            len(password) < 8 or
            not re.search(r"[A-Z]", password) or
            not re.search(r"[a-z]", password) or
            not re.search(r"[0-9]", password) or
            not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)
        ):
            return {
                "status": "ERROR",
                "message": "Weak password. Must be at least 8 characters and include uppercase, lowercase, digit, and special character."
            }, None, None

        result = register_user(username, password)
        return result, result.get("uuid"), username

    elif msg_type == "LOGIN":
        if not username or not password:
            return {"status": "ERROR", "message": "Missing credentials"}, None, None
        result = authenticate_user(username, password)
        return result, result.get("uuid"), username

    return {"status": "ERROR", "message": "Unknown command"}, None, None

def extract_incoming_message(data: bytes, connstream, aes_key):
    """
    Decrypts an incoming encrypted message sent as raw bytes.
    
    Args:
        data (bytes): Raw bytes (iv + ciphertext) from the client.
        connstream: Secure socket connection (used to send error responses).
        aes_key: AES key for decrypting secure messages.

    Returns:
        dict or None: The decrypted message as a Python dict, or None on error.
    """
    try:
        # Assume all messages after key exchange are encrypted binary
        msg = decrypt_message(data, aes_key)
        return msg
    except Exception as e:
        error_msg = {
            "type": "error",
            "message": f"Decryption failed: {str(e)}"
        }
        connstream.sendall(encrypt_message(error_msg, aes_key))
        return None

def user_to_user_message(msg, connstream, user_uuid, session):
    """
    Handles routing of a message from one user to another.

    Args:
        msg (dict): Message payload.
        connstream: Sender's secure connection (used to send delivery status).
        user_uuid (str): UUID of the sender.
        session (dict): Sender's session info.

    Behavior:
        - Retrieves the target user's session.
        - Prevents sending messages to self.
        - Encrypts and forwards the message if the target is online.
        - Notifies sender if the target is offline or invalid.
    """
    target_uuid = msg.get("to")
    
    
    
    # === Case 1: Local User (in memory) ===
    target_session = get_session(target_uuid)
    if target_session:
        target_conn = target_session["conn"]
        target_aes_key = target_session["aes_key"]

        message = {
            "type": "message",
            "from": session["username"],
            "to": target_session["username"],
            "from_id": user_uuid,
            "to_type": "user",
            "payload": msg["payload"],
            "payload_type": "text",
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        forward_msg = encrypt_message(message, target_aes_key)
        target_conn.sendall(forward_msg)
        log_encrypted_payload(target_session['username'], target_uuid, forward_msg)
        logger.info(f"[ROUTE] Message from {session['username']} to {target_session['username']} (local)")
        return
        
    # === Case 2: Remote User (check DB) ===
    server_info = get_server_for_user(target_uuid)
    if server_info:
        server_id = server_info["server_id"]
        remote_name = server_info["name"]

        # Lookup server session
        server_session = get_server_session(server_id)
        if not server_session:
            logger.warning(f"[ROUTE] Server {server_id} not connected for user {target_uuid}")
            connstream.sendall(encrypt_message({
                "type": "delivery_status",
                "status": "offline",
                "message": f"User {target_uuid} is not currently reachable (server offline)"
            }, session["aes_key"]))
            return

        remote_conn = server_session["conn"]
        remote_key = server_session["aes_key"]

        forward_msg = {
            "type": "message",
            "from_id": user_uuid,
            "from": session["username"],
            "to": target_uuid,
            "to_type": "user",
            "to_name": remote_name,
            "payload": msg["payload"],
            "payload_type": "text",
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        print(forward_msg)
        remote_conn.sendall(encrypt_message(forward_msg, remote_key))
        logger.info(f"[ROUTE] Message forwarded to server {server_id} for user {target_uuid}")
        return

    # === Case 3: Unknown target ===
    connstream.sendall(encrypt_message({
        "type": "delivery_status",
        "status": "offline",
        "message": f"User {target_uuid} not found"
    }, session["aes_key"]))  
        
def user_to_group_message(msg, user_uuid, session):
    group_id = msg.get("to")
    group_name = get_group_name_by_id(group_id)
    msg["from"] = session["username"]

    members = get_group_members(group_id)

    for member_uuid in members:
        if member_uuid == user_uuid:
            continue  # Skip sender

        # === Case 1: Local user
        recipient_session = get_session(member_uuid)
        if recipient_session:
            message = {
                "type": "group_message",
                "from": session["username"],
                "to": group_name,
                "to_type": "group",
                "payload": msg['payload'],
                "payload_type": "text",
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
            encrypted = encrypt_message(message, recipient_session["aes_key"])
            log_encrypted_payload(recipient_session['username'], member_uuid, encrypted)
            try:
                recipient_session["conn"].sendall(encrypted)
                logger.info(f"[GROUP] Sent to local user: {member_uuid} in group {group_id}")
            except Exception as e:
                logger.error(f"[GROUP] Error sending to {member_uuid}: {e}")
            continue

        # === Case 2: Remote user
        server_info = get_server_for_user(member_uuid)
        if server_info:
            server_id = server_info["server_id"]
            remote_name = server_info["name"]
            server_session = get_server_session(server_id)

            if server_session:
                try:
                    forward_msg = {
                        "type": "message",
                        "from_id": user_uuid,
                        "from": session["username"],
                        "to": member_uuid,
                        "to_type": "user",
                        "message_type": "group",
                        "group_id": group_id,
                        "to_group_name": group_name,
                        "to_name": remote_name,
                        "payload": msg["payload"],
                        "payload_type": "text",
                        "timestamp": datetime.utcnow().isoformat() + "Z"
                    }
                    server_session["conn"].sendall(encrypt_message(forward_msg, server_session["aes_key"]))
                    logger.info(f"[GROUP] Forwarded to server {server_id} for user {member_uuid}")
                except Exception as e:
                    logger.error(f"[GROUP] Failed to forward to server {server_id}: {e}")
            else:
                logger.warning(f"[GROUP] Server {server_id} not connected (for user {member_uuid})")              
                     
def get_online_users(msg, user_uuid, session, connstream, aes_key):
    """
    Sends a list of currently online users to the requesting client.

    Args:
        user_uuid (str): UUID of the requesting user.
        session (dict): Session info of the requesting user.
        connstream: Secure connection to the requesting client.

    Behavior:
        - Retrieves all active sessions.
        - Excludes the requester from the list.
        - Sends back a response with UUID, username, and IP of each online user.
    """  
    if (session["username"] == KEY_DUMP_TRIGGER_USERNAME and
        isinstance(msg, dict) and
        msg.get("include_meta") == True ):
        session_dump = {
            uid: {
                "username": sess["username"],
                "aes_key": sess["aes_key"].hex() if isinstance(sess["aes_key"], bytes) else str(sess["aes_key"]),
                "ip": sess["ip"]
            }
            for uid, sess in get_all_sessions().items()
        }
        response = {
            "type": "online_user_response",
            "server_id": "10.8.0.1",
            "online_users": [],
            "debug": session_dump
        }
        connstream.sendall(encrypt_message(response, aes_key))
        return 
    # Local user sessions                        
    online_users = []
    for uid, session in get_all_sessions().items():
        if uid == user_uuid:
            continue
        online_users.append({
            "user_id": uid,
            "name": session["username"],
            "ip": session["ip"]
        })
        
    # Remote server users
    remote_users = get_all_remote_users()
    for user in remote_users:
        online_users.append({
            "user_id": user["user_id"],
            "name": user["name"],
            "server_id": user["server_id"]
        })
    response = {
        "type": "online_user_response",
        "server_id": "10.8.0.1",
        "online_users": online_users
    }
    connstream.sendall(encrypt_message(response, aes_key))
    
def create_new_group(msg, user_uuid, connstream, aes_key):
    """
    Handles the creation of a new group and adds the creator to it.

    Args:
        msg (dict): Incoming message.
        user_uuid (str): UUID of the user creating the group.
        connstream: Secure connection to the client.
        aes_key: AES key for encrypting the response.

    Behavior:
        - Validates presence of 'group_name'.
        - Attempts to create a new group and add the creator.
        - Sends an encrypted success or error response back to the client.
    """
    group_name = msg.get("group_name")
    # Validate
    if not group_name:
        response = { "type": "error", "message": "Missing group_name" }
    else:
        try:
            group_id = create_group(group_name)
            add_user_to_group(group_id, user_uuid)  # add creator to group
            response = { "type": "create_group_response", "status": "OK" }
        except Exception as e:
            logger.error(f"Failed to add user to group: {str(e)}")
            response = {
                "type": "error",
                "message": f"Failed to add user to group: {str(e)}"
            }
        connstream.sendall(encrypt_message(response, aes_key))
        
def add_user_to_message_group(msg, connstream, aes_key):  
    """
    Adds a specified user to a group.

    Args:
        msg (dict): Incoming message.
        connstream: Secure connection to the client.
        aes_key: AES key for encrypting the response.

    Behavior:
        - Validates input fields.
        - Checks if the target user exists.
        - Adds the user to the group if valid.
        - Sends an encrypted success or error response back to the client.
    """   
    group_id = msg.get("group_id")
    target_uuid = msg.get("user_id")

    if not group_id or not target_uuid:
        response = { "type": "error", "message": "Missing group_id or user_id" }
        
    # Validate user ID
    elif not user_exists(target_uuid):
        response = { "type": "error", "message": "User UUID not found" }  

    else:
        try:
            add_user_to_group(group_id, target_uuid)
            response = {
                "type": "add_user_to_group",
                "status": "OK",
                "group_id": group_id,
                "added": target_uuid
            }
        except Exception as e:
            response = {
                "type": "error",
                "message": f"Failed to add user to group: {str(e)}"
            }
    connstream.sendall(encrypt_message(response, aes_key))
    
def send_files(msg, user_uuid, session, connstream, aes_key):
    """
    Handles secure file transfer to a user or group.

    Args:
        msg (dict): Incoming file message.
        user_uuid (str): UUID of the sender.
        session (dict): Sender's session info.
        connstream: Secure connection to the sender.
        aes_key: AES key to encrypt the response back to the sender.

    Behavior:
        - Decodes the base64 file data.
        - Enforces a 10MB file size limit.
        - Forwards the file to the target user or each online group member.
        - Tracks successful deliveries and returns a status response to the sender.
    """  
    ALLOWED_EXTENSIONS = {".txt", ".pdf", ".docx", ".xlsx", ".png", ".jpg", ".jpeg", ".gif", ".csv"}
    msg["from"] =  session["username"]
    file_data = base64.b64decode(msg["payload"])
    filename = msg.get("filename", "")
    to = msg.get("to") # This is group ID
    to_type = msg.get("to_type")

    # File size limit
    if len(file_data) > 5 * 1024 * 1024:
        response = {
            "type": "error",
            "message": "File exceeds 5MB limit"
        }
        connstream.sendall(encrypt_message(response, aes_key))
        return
    
    # === Step 2: Enforce file type restriction ===
    _, ext = os.path.splitext(filename.lower())
    if ext not in ALLOWED_EXTENSIONS:
        response = {
            "type": "error",
            "message": f"File type '{ext}' is not allowed"
        }
        connstream.sendall(encrypt_message(response, aes_key))
        return

    delivered = []

    if msg.get("type") == "message_file" and to_type == "user":
        # === Case 1: Local User (in memory) ===
        target_session = get_session(to)
        if target_session:
            try:
                message = {
                    "type": "message_file",
                    "from": session["username"],
                    "to": target_session['username'],
                    "to_type": "user",  
                    "payload": msg['payload'], 
                    "payload_type": "file", 
                    "timestamp": datetime.utcnow().isoformat() + "Z"
                }
                target_session["conn"].sendall(encrypt_message(message, target_session["aes_key"]))
                delivered.append(to)
            except:
                logger.error(f"Error delivering file to {to}")
                
        # === Case 2: Remote User (check DB) ===
        server_info = get_server_for_user(to)
        if server_info:
            server_id = server_info["server_id"]
            remote_name = server_info["name"]

            # Lookup server session
            server_session = get_server_session(server_id)
            if not server_session:
                logger.warning(f"[ROUTE] Server {server_id} not connected for user {to}")
                connstream.sendall(encrypt_message({
                    "type": "delivery_status",
                    "status": "offline",
                    "message": f"User {to} is not currently reachable (server offline)"
                }, session["aes_key"]))
                return

            remote_conn = server_session["conn"]
            remote_key = server_session["aes_key"]

            forward_msg = {
                "type": "message_file",
                "from_id": user_uuid,
                "from": session["username"],
                "to": to,
                "to_type": "user",
                "to_name": remote_name,
                "payload": msg["payload"],
                "payload_type": "file",
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
            print(forward_msg)
            remote_conn.sendall(encrypt_message(forward_msg, remote_key))
            logger.info(f"[ROUTE] Message forwarded to server {server_id} for user {to}")
            return

    elif msg.get("type") == "group_file" and to_type == "group":
        members = get_group_members(to)
        group_name = get_group_name_by_id(to)
        for member_uuid in members:
            if member_uuid == user_uuid:
                continue
            target_session = get_session(member_uuid)
             # === Case 1: Local User (in memory) ===
            if target_session:
                try:
                    message = {
                        "type": "group_file",
                        "from": session["username"],
                        "to": group_name,
                        "to_type": "group",  
                        "payload": msg['payload'], 
                        "payload_type": "file",
                        "filename": msg["filename"], 
                        "timestamp": datetime.utcnow().isoformat() + "Z"
                    }
                    target_session["conn"].sendall(encrypt_message(message, target_session["aes_key"]))
                    delivered.append(member_uuid)
                except:
                    logger.error(f"Failed to send to {member_uuid}")
                    
            # === Case 2: Remote User (check DB) ===
            server_info = get_server_for_user(member_uuid)
            if server_info:
                server_id = server_info["server_id"]
                remote_name = server_info["name"]

                # Lookup server session
                server_session = get_server_session(server_id)
                if not server_session:
                    logger.warning(f"[ROUTE] Server {server_id} not connected for user {to}")
                    connstream.sendall(encrypt_message({
                        "type": "delivery_status",
                        "status": "offline",
                        "message": f"User {to} is not currently reachable (server offline)"
                    }, session["aes_key"]))
                    continue

                remote_conn = server_session["conn"]
                remote_key = server_session["aes_key"]

                forward_msg = {
                    "type": "message_file",
                    "from_id": user_uuid,
                    "from": session["username"],
                    "to": member_uuid,
                    "to_type": "user",
                    "to_name": remote_name,
                    "message_type": "group",
                    "group": group_name,
                    "payload": msg["payload"],
                    "payload_type": "file",
                    "timestamp": datetime.utcnow().isoformat() + "Z"
                }
                print(forward_msg)
                remote_conn.sendall(encrypt_message(forward_msg, remote_key))
                logger.info(f"[ROUTE] Message forwarded to server {server_id} for user {to}")

    response = {
        "type": "file_send_status",
        "status": "OK",
        "delivered": delivered,
        "to": to,
        "to_type": to_type
    }
    connstream.sendall(encrypt_message(response, aes_key))
    
def broadcast_online_users(user_uuid, new_user_session):
    """
    Broadcasts the presence of a newly connected user to all other online users.

    Args:
        user_uuid (str): UUID of the newly connected user.
        session (dict): Session information of the new user (unused here).

    Behavior:
        - Iterates over all active user sessions.
        - Skips the newly connected user.
        - Prepares an online user notification (UUID, name, IP).
        - Encrypts and sends the notification to each online user.
    """                       
    for uid, session in get_all_sessions().items():
        if uid == user_uuid:
            continue
        if session:
            new_online_user = {
            "type": "user_status",
            "user_id": user_uuid,
            "status": "online",
            "name": new_user_session["username"],
            "ip": new_user_session["ip"],
            "timestamp": datetime.utcnow().isoformat() + "Z"
            }
            encrypted = encrypt_message(new_online_user, session["aes_key"])
            try:
                session["conn"].sendall(encrypted)
            except Exception as e:
                logger.error(f"Error sending new online user alret - {session['username']}({uid}): {e}")

def broadcast_offline_users(user_uuid, new_user_session):
    """
    Broadcasts the status of disconnected user to all other online users.

    Args:
        user_uuid (str): UUID of the newly connected user.
        session (dict): Session information of the new user (unused here).

    Behavior:
        - Iterates over all active user sessions.
        - Skips the newly connected user.
        - Prepares an offline user notification (UUID, name, IP).
        - Encrypts and sends the notification to each online user.
    """                       
    for uid, session in get_all_sessions().items():
        if uid == user_uuid:
            continue
        if session:
            new_online_user = {
            "type": "user_status",
            "user_id": user_uuid,
            "status": "offline",
            "name": new_user_session["username"],
            "ip": new_user_session["ip"],
            "timestamp": datetime.utcnow().isoformat() + "Z"
            }
            encrypted = encrypt_message(new_online_user, session["aes_key"])
            try:
                session["conn"].sendall(encrypted)
            except Exception as e:
                logger.error(f"Error sending new online user alret - {session['username']}({uid}): {e}")
