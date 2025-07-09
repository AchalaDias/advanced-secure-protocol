import mysql.connector
import bcrypt
import uuid
from .db_config import DB_CONFIG


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
    except mysql.connector.errors.IntegrityError:
        return {"status": "ERROR", "message": "Username already exists"}
    finally:
        conn.close()


def authenticate_user(username, password):
    conn = get_db_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT uuid, password FROM users WHERE username=%s", (username,))
    results = cursor.fetchall()
    conn.close()

    for user_uuid, stored_hash in results:
        if bcrypt.checkpw(password.encode(), stored_hash.encode() if isinstance(stored_hash, str) else stored_hash):
            return {
                "status": "OK",
                "message": "Login successful",
                "uuid": user_uuid,
                "username": username
            }
    return {"status": "ERROR", "message": "Invalid credentials"}