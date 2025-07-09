import socket
import ssl
import json

def send_json_request(data, host='127.0.0.1', port=5001):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port)) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            ssock.sendall(json.dumps(data).encode())
            response = ssock.recv(2048).decode()
            return json.loads(response)

def test_register(username, password):
    print(f"[TEST] Registering user: {username}")
    response = send_json_request({
        "type": "REGISTER",
        "username": username,
        "password": password
    })
    print(f"[RESULT] {response}")

def test_login(username, password):
    print(f"[TEST] Logging in as: {username}")
    response = send_json_request({
        "type": "LOGIN",
        "username": username,
        "password": password
    })
    print(f"[RESULT] {response}")

if __name__ == "__main__":
    # Test user registration and login
    test_register("alice", "secure123")
    test_login("alice", "secure123")

    # Try logging in with wrong password
    test_login("alice", "wrongpass")

    # Try registering existing user again
    test_register("alice", "anotherpass")
