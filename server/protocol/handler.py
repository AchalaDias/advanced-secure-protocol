import json
from db.user_model import register_user, authenticate_user


def process_message(raw_data, conn=None):
    try:
        data = json.loads(raw_data)
    except json.JSONDecodeError:
        return {"status": "ERROR", "message": "Invalid JSON"}, None, None

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

