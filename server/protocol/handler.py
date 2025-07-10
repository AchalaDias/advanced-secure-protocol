import json
from db.user_model import register_user, authenticate_user
from protocol.crypto import decrypt_message

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

