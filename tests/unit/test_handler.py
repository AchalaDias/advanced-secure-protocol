## Group Name & Members
# - Group Name: Group Project 8
# - Anthonan Hettige Achala Tharaka Dias (a1933508)
# - Sanjida Amrin (a1934493)
# - Zahin Rydha (a1938252)

import base64

# extract_incoming_message
def test_extract_incoming_message_success(H, patch, fake_conn, aes_key, stub_decrypt, stub_encrypt):
    patch("decrypt_message", lambda data, key: {"ok": True})
    patch("encrypt_message", stub_encrypt)
    out = H.extract_incoming_message(b'ENC[{"ok":true}]', fake_conn, aes_key)
    assert out == {"ok": True}
    assert fake_conn.sent == b""

def test_extract_incoming_message_failure_sends_error(H, patch, fake_conn, aes_key, stub_encrypt):
    patch("decrypt_message", lambda *_: (_ for _ in ()).throw(RuntimeError("boom")))
    patch("encrypt_message", stub_encrypt)
    out = H.extract_incoming_message(b"...", fake_conn, aes_key)
    assert out is None
    # error response is encrypted JSON including message
    assert b"ENC[" in fake_conn.sent
    assert b"Decryption failed" in fake_conn.sent

# user_to_user_message
def test_user_to_user_message_prevents_self(H, patch, fake_conn, aes_key, stub_encrypt):
    # message addressed to self -> your handler echoes a normal "message"
    msg = {"to": "userA", "payload": "hi"}
    session = {"username": "achala", "aes_key": aes_key}
    patch("get_session", lambda uid: {"conn": fake_conn, "aes_key": aes_key, "username": "achala"} if uid == "userA" else None)
    patch("encrypt_message", stub_encrypt)

    H.user_to_user_message(msg, fake_conn, user_uuid="userA", session=session)

    assert fake_conn.sent, "expects an echo back to the sender"
    assert b'"type":"message"' in fake_conn.sent

def test_user_to_user_message_local_delivery(H, patch, aes_key, stub_encrypt):
    c_to = type("C", (), {"sent": bytearray(), "sendall": lambda self, b: self.sent.extend(b)})()
    sender_conn = type("C", (), {"sent": bytearray(), "sendall": lambda self, b: self.sent.extend(b)})()
    session = {"username": "achala", "aes_key": aes_key}
    target_sess = {"conn": c_to, "aes_key": b"\x22"*32, "username": "tom"}
    patch("get_session", lambda uid: target_sess if uid == "userB" else None)
    patch("encrypt_message", stub_encrypt)

    H.user_to_user_message({"to": "userB", "payload": "hi"}, sender_conn, "userA", session)

    # forwarded to the target
    assert c_to.sent, "target must get bytes"
    # and the function should not send an error back to sender in this success case
    assert not sender_conn.sent

def test_user_to_user_message_remote_offline_server(H, patch, fake_conn, aes_key, stub_encrypt):
    session = {"username": "achala", "aes_key": aes_key}
    patch("get_session", lambda *_: None)
    patch("get_server_for_user", lambda *_: {"server_id": "s1", "name": "remote"})  # remote user
    patch("get_server_session", lambda *_: None)  # but server not connected
    patch("encrypt_message", stub_encrypt)

    H.user_to_user_message({"to": "u9", "payload": "x"}, fake_conn, "userA", session)

    assert b"delivery_status" in fake_conn.sent and b"offline" in fake_conn.sent

def test_user_to_user_message_remote_forward(H, patch, aes_key, stub_encrypt):
    sender_conn = type("C", (), {"sent": bytearray(), "sendall": lambda self, b: self.sent.extend(b)})()
    remote_conn = type("C", (), {"sent": bytearray(), "sendall": lambda self, b: self.sent.extend(b)})()
    session = {"username": "achala", "aes_key": aes_key}
    patch("get_session", lambda *_: None)
    patch("get_server_for_user", lambda *_: {"server_id": "s1", "name": "remote"})
    patch("get_server_session", lambda *_: {"conn": remote_conn, "aes_key": b"\x33"*32})
    patch("encrypt_message", stub_encrypt)

    H.user_to_user_message({"to": "u9", "payload": "x"}, sender_conn, "userA", session)

    assert remote_conn.sent, "should forward to remote server"
    assert not sender_conn.sent  # no error to sender

def test_user_to_user_message_unknown_target(H, patch, fake_conn, aes_key, stub_encrypt):
    patch("get_session", lambda *_: None)
    patch("get_server_for_user", lambda *_: None)
    patch("encrypt_message", stub_encrypt)

    H.user_to_user_message({"to": "ghost", "payload": "x"}, fake_conn, "userA", {"username": "achala", "aes_key": aes_key})

    assert b"User ghost not found" in fake_conn.sent

# user_to_group_message
def test_user_to_group_message_fanout_local_and_remote(H, patch, aes_key, stub_encrypt):
    # group has three members, one is sender, one local, one remote
    group_id = "g1"
    members = ["u_sender", "u_local", "u_remote"]
    c_local = type("C", (), {"sent": bytearray(), "sendall": lambda self, b: self.sent.extend(b)})()

    patch("get_group_name_by_id", lambda gid: "Cool Group")
    patch("get_group_members", lambda gid: members)
    patch("get_session", lambda uid: {"conn": c_local, "aes_key": b"\x44"*32, "username": "tom"} if uid=="u_local" else None)
    patch("get_server_for_user", lambda uid: {"server_id": "s1", "name": "remote"} if uid == "u_remote" else None)
    patch("get_server_session", lambda sid: {"conn": type("RC", (), {"sent": bytearray(), "sendall": lambda self, b: self.sent.extend(b)})(), "aes_key": b"\x55"*32})
    patch("encrypt_message", stub_encrypt)

    H.user_to_group_message({"to": group_id, "payload": "hey"}, "u_sender", {"username": "achala"})

    assert c_local.sent, "local member should receive"

# get_online_users
def test_get_online_users_normal(H, patch, fake_conn, aes_key, stub_encrypt):
    patch("get_all_sessions", lambda: {"userA": {"username":"a","ip":"1.1.1.1"}, "userB":{"username":"b","ip":"2.2.2.2"}})
    patch("get_all_remote_users", lambda: [{"user_id":"r1","name":"Rita","server_id":"s9"}])
    patch("encrypt_message", stub_encrypt)

    # requester = userA; should only see userB + remote users
    H.get_online_users({}, "userA", fake_conn, aes_key)

    assert fake_conn.sent, "expected a response to be sent"
    s = fake_conn.sent.decode()
    assert '"user_id":"userB"' in s and '"r1"' in s

# create_new_group
def test_create_new_group_missing_name(H, patch, fake_conn, aes_key, stub_encrypt):
    patch("encrypt_message", stub_encrypt)

    H.create_new_group({}, "userA", fake_conn, aes_key)

    assert fake_conn.sent == b""

def test_create_new_group_success(H, patch, fake_conn, aes_key, stub_encrypt):
    patch("encrypt_message", stub_encrypt)
    patch("create_group", lambda name: "g1")
    patch("add_user_to_group", lambda gid, uid: None)

    H.create_new_group({"group_name":"devs"}, "userA", fake_conn, aes_key)

    assert b"create_group_response" in fake_conn.sent and b"OK" in fake_conn.sent

def test_create_new_group_error_on_add(H, patch, fake_conn, aes_key, stub_encrypt):
    patch("encrypt_message", stub_encrypt)
    patch("create_group", lambda name: "g1")
    patch("add_user_to_group", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("db down")))

    H.create_new_group({"group_name":"devs"}, "userA", fake_conn, aes_key)

    assert b"error" in fake_conn.sent and b"Failed to add user to group" in fake_conn.sent

# add_user_to_message_group
def test_add_user_to_message_group_validations(H, patch, fake_conn, aes_key, stub_encrypt):
    patch("encrypt_message", stub_encrypt)

    # missing group_id
    H.add_user_to_message_group({"username":"tom"}, fake_conn, aes_key)
    assert b"Missing group_id or user_id" in fake_conn.sent
    fake_conn.sent.clear()

    # missing user_id
    H.add_user_to_message_group({"group_id":"g1"}, fake_conn, aes_key)
    assert b"Missing group_id or user_id" in fake_conn.sent

def test_add_user_to_message_group_user_not_exist(H, patch, fake_conn, aes_key, stub_encrypt):
    patch("encrypt_message", stub_encrypt)
    patch("user_exists", lambda u: False)

    H.add_user_to_message_group({"group_id":"g1","user_id":"ghost"}, fake_conn, aes_key)

    assert b"User UUID not found" in fake_conn.sent

def test_add_user_to_message_group_success(H, patch, fake_conn, aes_key, stub_encrypt):
    patch("encrypt_message", stub_encrypt)
    patch("user_exists", lambda u: True)
    patch("add_user_to_group", lambda gid, uid: None)

    H.add_user_to_message_group({"group_id":"g1","user_id":"userB"}, fake_conn, aes_key)

    assert b'"status":"OK"' in fake_conn.sent or b'"status": "OK"' in fake_conn.sent

# send_files
ALLOWED = {".txt", ".pdf", ".docx", ".xlsx", ".png", ".jpg", ".jpeg", ".gif", ".csv"}

def test_send_files_size_limit(H, patch, fake_conn, aes_key, stub_encrypt):
    big = base64.b64encode(b"x" * (10*1024*1024 + 1)).decode()
    patch("encrypt_message", stub_encrypt)
    patch("get_session", lambda *_: None)
    msg = {"type":"message_file","to_type":"user","to":"userB","payload":"data:"+big,"filename":"f.txt"}

    H.send_files(msg, "userA", {"username":"achala","aes_key":aes_key}, fake_conn, aes_key)

    assert b"exceeds" in fake_conn.sent

def test_send_files_type_restricted(H, patch, fake_conn, aes_key, stub_encrypt):
    data = base64.b64encode(b"hello").decode()
    patch("encrypt_message", stub_encrypt)
    msg = {"type":"message_file","to_type":"user","to":"userB","payload":data,"filename":"malware.exe"}

    H.send_files(msg, "userA", {"username":"achala","aes_key":aes_key}, fake_conn, aes_key)

    assert b"not allowed" in fake_conn.sent

def test_send_files_local_user_delivery(H, patch, aes_key, stub_encrypt):
    target_conn = type("C", (), {"sent": bytearray(), "sendall": lambda self, b: self.sent.extend(b)})()
    patch("encrypt_message", stub_encrypt)
    patch("get_session", lambda uid: {"conn": target_conn, "aes_key": b"\xAA"*32, "username":"tom"} if uid=="userB" else None)
    # Avoid DB lookup — treat user as local
    patch("get_server_for_user", lambda *_: None)

    data = base64.b64encode(b"hello").decode()
    msg = {"type":"message_file","to_type":"user","to":"userB","payload":data,"filename":"f.txt"}
    sender_conn = type("C", (), {"sent": bytearray(), "sendall": lambda self, b: self.sent.extend(b)})()

    H.send_files(msg, "userA", {"username":"achala","aes_key":b"\xBB"*32}, sender_conn, b"\xBB"*32)

    assert target_conn.sent, "target should receive file"
    assert b"file_send_status" in sender_conn.sent

def test_send_files_remote_user_forward(H, patch, aes_key, stub_encrypt):
    remote_conn = type("RC", (), {"sent": bytearray(), "sendall": lambda self, b: self.sent.extend(b)})()
    patch("encrypt_message", stub_encrypt)
    patch("get_session", lambda *_: None)
    patch("get_server_for_user", lambda *_: {"server_id":"s1","name":"remote"})
    patch("get_server_session", lambda *_: {"conn": remote_conn, "aes_key": b"\xCC"*32})

    data = base64.b64encode(b"hello").decode()
    msg = {"type":"message_file","to_type":"user","to":"u9","payload":data,"filename":"f.txt"}
    sender_conn = type("C", (), {"sent": bytearray(), "sendall": lambda self, b: self.sent.extend(b)})()

    H.send_files(msg, "userA", {"username":"achala","aes_key":b"\xDD"*32}, sender_conn, b"\xDD"*32)

    assert remote_conn.sent

def test_send_files_group_local_and_remote(H, patch, aes_key, stub_encrypt):
    c_local = type("C", (), {"sent": bytearray(), "sendall": lambda self, b: self.sent.extend(b)})()
    r_conn = type("RC", (), {"sent": bytearray(), "sendall": lambda self, b: self.sent.extend(b)})()

    patch("encrypt_message", stub_encrypt)
    patch("get_group_members", lambda gid: ["u_sender","u_local","u_remote"])
    patch("get_group_name_by_id", lambda gid: "Team")
    patch("get_session", lambda uid: {"conn": c_local, "aes_key": b"\xEE"*32, "username":"tom"} if uid=="u_local" else None)
    patch("get_server_for_user", lambda uid: {"server_id":"s1","name":"remote"} if uid=="u_remote" else None)
    patch("get_server_session", lambda sid: {"conn": r_conn, "aes_key": b"\xFF"*32})

    payload = base64.b64encode(b"hello").decode()
    msg = {"type":"group_file","to_type":"group","to":"g1","payload":payload,"filename":"f.txt"}
    sender_conn = type("C", (), {"sent": bytearray(), "sendall": lambda self, b: self.sent.extend(b)})()

    H.send_files(msg, "u_sender", {"username":"achala","aes_key":b"\xAB"*32}, sender_conn, b"\xAB"*32)

    assert c_local.sent or r_conn.sent
    assert b"file_send_status" in sender_conn.sent

# broadcast_* presence notifications
def test_broadcast_online_users(H, patch, aes_key, stub_encrypt):
    c1 = type("C", (), {"sent": bytearray(), "sendall": lambda self, b: self.sent.extend(b)})()
    c2 = type("C", (), {"sent": bytearray(), "sendall": lambda self, b: self.sent.extend(b)})()
    sessions = {
        "userA": {"conn": c1, "aes_key": aes_key, "username":"a", "ip":"1.1.1.1"},
        "userB": {"conn": c2, "aes_key": aes_key, "username":"b", "ip":"2.2.2.2"},
    }
    patch("get_all_sessions", lambda: sessions)
    patch("encrypt_message", stub_encrypt)

    H.broadcast_online_users("userA", {"username": "a", "ip":"1.1.1.1"})

    # userB should get a notice; userA is skipped
    assert not c1.sent and c2.sent

def test_broadcast_offline_users(H, patch, aes_key, stub_encrypt):
    c1 = type("C", (), {"sent": bytearray(), "sendall": lambda self, b: self.sent.extend(b)})()
    c2 = type("C", (), {"sent": bytearray(), "sendall": lambda self, b: self.sent.extend(b)})()
    sessions = {
        "userA": {"conn": c1, "aes_key": aes_key, "username":"a", "ip":"1.1.1.1"},
        "userB": {"conn": c2, "aes_key": aes_key, "username":"b", "ip":"2.2.2.2"},
    }
    patch("get_all_sessions", lambda: sessions)
    patch("encrypt_message", stub_encrypt)

    H.broadcast_offline_users("userA", {"username": "a", "ip":"1.1.1.1"})

    assert not c1.sent and c2.sent
