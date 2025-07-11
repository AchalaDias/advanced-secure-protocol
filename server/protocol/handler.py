import json, base64
from db.user_model import register_user, authenticate_user, user_exists
from protocol.crypto import decrypt_message, encrypt_message
from db.group_model import get_group_members, add_user_to_group, create_group
from protocol.session_manager import get_session, get_all_sessions, get_session_by_socket

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
        
def user_to_group_message(msg, user_uuid, session):
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
                print(f"[!] Error sending to {member_uuid}: {e}")
                     
def get_online_users(user_uuid, session, connstream):                          
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
            response = {
                "type": "error",
                "message": f"Failed to add user to group: {str(e)}"
            }
        connstream.sendall(json.dumps(encrypt_message(response, aes_key)).encode())
        
def add_user_to_message_group(msg, connstream, aes_key):     
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
                print(f"[!] Error delivering file to {to}")

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
                    print(f"[!] Failed to send to {member_uuid}")

    response = {
        "type": "file_send_status",
        "status": "OK",
        "delivered": delivered,
        "to": to,
        "to_type": to_type
    }
    connstream.sendall(json.dumps(encrypt_message(response, aes_key)).encode())