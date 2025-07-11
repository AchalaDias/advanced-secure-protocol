import json, base64
from protocol.logger import get_logger
from db.user_model import register_user, authenticate_user, user_exists
from protocol.crypto import decrypt_message, encrypt_message
from db.group_model import get_group_members, add_user_to_group, create_group
from protocol.session_manager import get_session, get_all_sessions

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
        result = register_user(username, password)
        return result, result.get("uuid"), username

    elif msg_type == "LOGIN":
        if not username or not password:
            return {"status": "ERROR", "message": "Missing credentials"}, None, None
        result = authenticate_user(username, password)
        return result, result.get("uuid"), username

    return {"status": "ERROR", "message": "Unknown command"}, None, None

def extract_incoming_message(data, connstream, aes_key):
    """
    Parses and decrypts an incoming message.

    Args:
        data (str): JSON-encoded message from the client.
        connstream: Secure socket connection (used to send error responses).
        aes_key: AES key for decrypting secure messages.

    Returns:
        dict or None: The parsed (and decrypted if needed) message, or None on error.
    """
    msg = {}
    try:
        raw = json.loads(data)            
    except json.JSONDecodeError:
        connstream.sendall(json.dumps({
            "type": "error",
            "message": "Invalid JSON"
        }).encode())
        return

    # Decrypt secure payload
    if raw.get("type") == "secure":
        try:
            msg = decrypt_message(raw, aes_key)
        except Exception as e:
            connstream.sendall(json.dumps({
                "type": "error",
                "message": f"Decryption failed: {str(e)}"
            }).encode())
            return
    else:
        msg = raw 
    return msg

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
    target_session = get_session(target_uuid)
    target_aes_key = target_session["aes_key"]
                    
    # Avoid sending messaged to same session
    if user_uuid == target_uuid:
        return

    if target_session:
        target_conn = target_session["conn"]
        msg['from'] = session["username"]
        message_to = f"{msg['to']} - {target_session['username']}"
        del msg['to']
      
        forward_msg = encrypt_message(msg, target_aes_key) 
        target_conn.sendall(json.dumps(forward_msg).encode())
        logger.info(f"[ROUTE] Message from {msg['from']} to {message_to} routed")
    else:
        connstream.sendall(json.dumps({
            "type": "delivery_status",
            "status": "offline",
            "message": f"User {target_uuid} is offline or Invalid"
        }).encode())
        
def user_to_group_message(msg, user_uuid, session):
    """
    Sends a message from a user to all members of a group.

    Args:
        msg (dict): The message payload.
        user_uuid (str): UUID of the sender.
        session (dict): Sender's session info.

    Behavior:
        - Adds sender's username to the message.
        - Retrieves group members using the group_id.
        - Encrypts the message with each recipient's AES key.
        - Sends the encrypted message to each online group member.
    """
    group_id = msg.get("to")
    msg["from"] =  session["username"]
    # Lookup group members
    members = get_group_members(group_id)
    
    for member_uuid in members:
        if member_uuid == user_uuid:
            continue  # Skip sender
        
        recipient_session = get_session(member_uuid)
        if recipient_session:
            encrypted = encrypt_message(msg, recipient_session["aes_key"])
            try:
                recipient_session["conn"].sendall(json.dumps(encrypted).encode())
            except Exception as e:
                logger.error(f"[!] Error sending to {member_uuid}: {e}")               
                     
def get_online_users(user_uuid, session, connstream):
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
    online_users = []
    for uid, session in get_all_sessions().items():
        if uid == user_uuid:
            continue
        online_users.append({
            "uuid": uid,
            "name": session["username"],
            "ip": session["ip"]
        })
    response = {
        "type": "online_user_response",
        "server_id": "10.8.0.1",
        "online_users": online_users
    }
    connstream.sendall(json.dumps(response).encode())
    
def create_group_message(msg, user_uuid, connstream, aes_key):
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
        connstream.sendall(json.dumps(encrypt_message(response, aes_key)).encode())
        
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
    connstream.sendall(json.dumps(encrypt_message(response, aes_key)).encode())
    
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
    msg["from"] =  session["username"]
    file_data = base64.b64decode(msg["payload"])
    to = msg.get("to")
    to_type = msg.get("to_type")

    # File size limit
    if len(file_data) > 10 * 1024 * 1024:
        response = {
            "type": "error",
            "message": "File exceeds 10MB limit"
        }
        connstream.sendall(json.dumps(encrypt_message(response, aes_key)).encode())
        return

    delivered = []

    if msg.get("type") == "message_file" and to_type == "user":
        session = get_session(to)
        if session:
            try:
                session["conn"].sendall(json.dumps(encrypt_message(msg, session["aes_key"])).encode())
                delivered.append(to)
            except:
                logger.error(f"Error delivering file to {to}")

    elif msg.get("type") == "group_file" and to_type == "group":
        members = get_group_members(to)
        for member_uuid in members:
            if member_uuid == user_uuid:
                continue
            session = get_session(member_uuid)
            if session:
                try:
                    session["conn"].sendall(json.dumps(encrypt_message(msg, session["aes_key"])).encode())
                    delivered.append(member_uuid)
                except:
                    logger.error(f"Failed to send to {member_uuid}")

    response = {
        "type": "file_send_status",
        "status": "OK",
        "delivered": delivered,
        "to": to,
        "to_type": to_type
    }
    connstream.sendall(json.dumps(encrypt_message(response, aes_key)).encode())
    
def broadcast_online_users(user_uuid, session, connstream):
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
    for uid, session in get_all_sessions().items():
        if uid == user_uuid:
            continue
        new_online_user = {
            "uuid": uid,
            "name": session["username"],
            "ip": session["ip"]
        }
        if session:
            encrypted = encrypt_message(new_online_user, session["aes_key"])
            try:
                session["conn"].sendall(json.dumps(encrypted).encode())
            except Exception as e:
                logger.error(f"Error sending to new online user alret - {session["username"]}({uid}): {e}")
