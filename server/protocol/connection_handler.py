import json, base64
from protocol.handler import process_message, extract_incoming_message
from protocol.session_manager import register_session, remove_session, get_session, get_all_sessions, get_session_by_socket
from db.group_model import create_group, add_user_to_group, get_groups_by_user, get_group_members
from db.user_model import user_exists

from protocol.crypto import (
    generate_rsa_key_pair,
    serialize_public_key,
    decrypt_aes_key,
    encrypt_message
)

def handle_client_connection(connstream, addr):
    print(f"[+] Connection from {addr}")
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
        print("Public Key Sent")
    except Exception as e:
        print(f"[!] Failed to send public key: {e}")
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
        print(f"[!] Failed to receive AES key: {e}")
        return

    try:
        # Read incoming data stream
        data = connstream.recv(2048).decode()
        if not data:
            return
        msg = extract_incoming_message(data, connstream, aes_key)     
    
        response_data, user_uuid, username = process_message(msg, connstream)
        if user_uuid:
            register_session(user_uuid, username, connstream, aes_key)
            
        connstream.sendall(json.dumps(response_data).encode())

        # Loop for messages or commands
        while True:
            data = connstream.recv(10 * 1024 * 1024).decode()
            if not data:
                break
            
            msg = extract_incoming_message(data, connstream, aes_key)
                
            try:
                # Validate session
                user_uuid, session = get_session_by_socket(connstream)
                if not session:
                    connstream.sendall(json.dumps({
                        "type": "error",
                        "message": "Unauthorized connection"
                    }).encode())
                    break
             
# =================================== User to User Messaging ====================================================  
                if msg.get("type") == "message" and msg.get("to_type") == "user":
                    target_uuid = msg.get("to")
                    target_session = get_session(target_uuid)
                    target_aes_key = target_session["aes_key"]
                    
                    # Avoid sending messaged to same session
                    if user_uuid == target_uuid:
                        break

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
                
                #  Broadcast Message to Group Members 
                elif msg.get("type") == "message" and msg.get("to_type") == "group":
                    from_uuid, from_session = get_session_by_socket(connstream)
                    group_id = msg.get("to")
                    msg["from"] =  from_session["username"]
                    # Lookup group members
                    members = get_group_members(group_id)
                    
                    for member_uuid in members:
                        if member_uuid == from_uuid:
                            continue  # Skip sender
                        
                        recipient_session = get_session(member_uuid)
                        if recipient_session:
                            encrypted = encrypt_message(msg, recipient_session["aes_key"])
                            try:
                                recipient_session["conn"].sendall(json.dumps(encrypted).encode())
                            except Exception as e:
                                print(f"[!] Error sending to {member_uuid}: {e}")
                
                
                        
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
# ========================================================================================================

# =================================== Group Messaging ====================================================     
                
                elif msg.get("type") == "create_group":
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
                            response = { "type": "error", "message": str(e) }

                    connstream.sendall(json.dumps(encrypt_message(response, aes_key)).encode())

                elif msg.get("type") == "list_my_groups":
                    groups = get_groups_by_user(user_uuid)
                    response = {
                        "type": "list_my_groups",
                        "groups": groups
                    }
                    connstream.sendall(json.dumps(encrypt_message(response, aes_key)).encode())    
                        
                elif msg.get("type") == "add_user_to_group":
                    group_id = msg.get("group_id")
                    target_uuid = msg.get("user_id")

                    if not group_id or not target_uuid:
                        response = { "type": "error", "message": "Missing group_id or user_id" }
                        
                    # Validate user ID
                    elif not user_exists(target_uuid):
                        response = { "type": "error", "message": "User UUID not found" }  
                    # else:
                    #     pass
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
                
                
# =======================================================================================================

# =================================== File Transfering ====================================================            
                elif msg.get("type") in ["message_file", "group_file"]:
                    from_uuid, from_session = get_session_by_socket(connstream)
                    msg["from"] =  from_session["username"]
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
                            if member_uuid == from_uuid:
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
       
# =======================================================================================================        
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
