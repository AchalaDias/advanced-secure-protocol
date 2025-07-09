import json
from protocol.handler import process_message
from protocol.session_manager import register_session, remove_session, get_session, get_all_sessions, get_session_by_socket

def handle_client_connection(connstream, addr):
    print(f"[+] Connection from {addr}")
    user_uuid = None

    try:
        # Initial login/register
        data = connstream.recv(2048).decode()
        if not data:
            return

        response_data, user_uuid, username = process_message(data, connstream)
        if user_uuid:
            register_session(user_uuid, username, connstream)

        connstream.sendall(json.dumps(response_data).encode())

        # Loop for messages or commands
        while True:
            data = connstream.recv(2048)
            if not data:
                break

            try:
                msg = json.loads(data.decode())
                
                # Validate session
                user_uuid, session = get_session_by_socket(connstream)
                if not session:
                    connstream.sendall(json.dumps({
                        "type": "error",
                        "message": "Unauthorized connection"
                    }).encode())
                    break
                
                if msg.get("type") == "message":
                    target_uuid = msg.get("to")
                    target_session = get_session(target_uuid)
                    
                    # Avoid sending messaged to same session
                    if user_uuid == target_uuid:
                        break

                    if target_session:
                        target_conn = target_session["conn"]
                        msg['from'] = session["username"]
                        message_to = f"{msg['to']} - {target_session['username']}"
                        del msg['to']
                        target_conn.sendall(json.dumps(msg).encode())
                        print(f"[ROUTE] Message from {msg['from']} to {message_to} routed")
                    else:
                        connstream.sendall(json.dumps({
                            "type": "delivery_status",
                            "status": "offline",
                            "message": f"User {target_uuid} is offline or Invalid"
                        }).encode())
                        
                elif msg.get("type") == "get_online_users":
                    # Need to hid the requested user's data                    
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
                else:
                    connstream.sendall(json.dumps({
                        "type": "error",
                        "message": "Unknown message type"
                    }).encode())
            except Exception as msg_err:
                print(f"Failed to process message: {msg_err}")
                connstream.sendall(json.dumps({
                    "type": "error",
                    "message": "Failed to parse message"
                }).encode())

    except Exception as e:
        print(f"[!] Exception with {addr}: {e}")
    finally:
        if user_uuid:
            remove_session(user_uuid)
        connstream.close()
