import json
from db.user_model import register_user, authenticate_user
from protocol.crypto import decrypt_message, encrypt_message
from db.group_model import create_group, add_user_to_group, get_groups_by_user
from protocol.session_manager import register_session, remove_session, get_session, get_all_sessions, get_session_by_socket

def process_message(data, conn=None):
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
        print(f"[ROUTE] Message from {msg['from']} to {message_to} routed")
    else:
        connstream.sendall(json.dumps({
            "type": "delivery_status",
            "status": "offline",
            "message": f"User {target_uuid} is offline or Invalid"
        }).encode())