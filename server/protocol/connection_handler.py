import json, base64
from protocol.handler import process_message, extract_incoming_message
from protocol.session_manager import register_session, remove_session, get_session, get_all_sessions, get_session_by_socket
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
        # try:
        #     raw = json.loads(data)            
        # except json.JSONDecodeError:
        #     connstream.sendall(json.dumps({
        #         "type": "error",
        #         "message": "Invalid JSON"
        #     }).encode())
        #     return

        # # Decrypt secure payload
        # if raw.get("type") == "secure":
        #     try:
        #         msg = decrypt_message(raw, aes_key)
        #     except Exception as e:
        #         connstream.sendall(json.dumps({
        #             "type": "error",
        #             "message": f"Decryption failed: {str(e)}"
        #         }).encode())
        #         return
        # else:
        #     msg = raw  # fallback for plain message
            
            
            
            
            
    
        response_data, user_uuid, username = process_message(msg, connstream)
        if user_uuid:
            register_session(user_uuid, username, connstream, aes_key)
            
        connstream.sendall(json.dumps(response_data).encode())

        # Loop for messages or commands
        while True:
            data = connstream.recv(2048).decode()
            if not data:
                break
            
            msg = extract_incoming_message(data, connstream, aes_key)
            # try:
            #     raw = json.loads(data)
            # except json.JSONDecodeError:
            #     connstream.sendall(json.dumps({
            #         "type": "error",
            #         "message": "Invalid JSON"
            #     }).encode())
            #     return

            # # Decrypt secure payload
            # if raw.get("type") == "secure":
            #     try:
            #         msg = decrypt_message(raw, aes_key)
            #     except Exception as e:
            #         connstream.sendall(json.dumps({
            #             "type": "error",
            #             "message": f"Decryption failed: {str(e)}"
            #         }).encode())
            #         return
            # else:
            #     msg = raw  # fallback for plain message
                
            try:
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
