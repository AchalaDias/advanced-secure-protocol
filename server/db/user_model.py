# server/db/user_model.py
import mysql.connector
from .db_config import DB_CONFIG
import bcrypt
import uuid

def get_db_conn():
    return mysql.connector.connect(**DB_CONFIG)

def register_user(username, password):
    conn = get_db_conn()
    cursor = conn.cursor()

    hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    user_uuid = str(uuid.uuid4())

    try:
        cursor.execute(
            "INSERT INTO users (uuid, username, password) VALUES (%s, %s, %s)",
            (user_uuid, username, hashed_pw)
        )
        conn.commit()
        return {
            "status": "OK",
            "message": "Registered",
            "uuid": user_uuid,
            "username": username
        }
    finally:
        conn.close()

def authenticate_user(username, password):
    conn = get_db_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM users WHERE username=%s", (username,))
    result = cursor.fetchone()
    conn.close()

    if result:
        stored_hash = result[0].encode() if isinstance(result[0], str) else result[0]
        if bcrypt.checkpw(password.encode(), stored_hash):
            return {"status": "OK", "message": "Login successful"}
    return {"status": "ERROR", "message": "Invalid credentials"}
