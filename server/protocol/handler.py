# server/protocol/handler.py

import json
from db.user_model import register_user, authenticate_user

def process_message(raw_data):
    try:
        data = json.loads(raw_data)
    except json.JSONDecodeError:
        return json.dumps({"status": "ERROR", "message": "Invalid JSON"})

    msg_type = data.get("type")
    username = data.get("username")
    password = data.get("password")

    if msg_type == "REGISTER":
        if not username or not password:
            return json.dumps({"status": "ERROR", "message": "Missing credentials"})
        return json.dumps(register_user(username, password))

    elif msg_type == "LOGIN":
        if not username or not password:
            return json.dumps({"status": "ERROR", "message": "Missing credentials"})
        return json.dumps(authenticate_user(username, password))

    else:
        return json.dumps({"status": "ERROR", "message": "Unknown command"})
