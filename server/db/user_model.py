## Group Name & Members
# - Group Name: Group Project 8
# - Anthonan Hettige Achala Tharaka Dias (a1933508)
# - Sanjida Amrin (a1934493)
# - Zahin Rydha (a1938252)

import mysql.connector
import bcrypt
import uuid
from .db_config import DB_CONFIG

def get_db_conn():
    """ Initializing the db connection """
    return mysql.connector.connect(**DB_CONFIG)

def register_user(username, password):
    """
    Registers a new user in the database.

    Args:
        username (str): The desired username.
        password (str): The user's plaintext password.

    Returns:
        dict: A response indicating success or failure.
            On success: includes status, message, uuid, and username.
            On failure: includes status and error message.
    """
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
    """
    Authenticates a user by verifying their credentials.

    Args:
        username (str): The username of the user.
        password (str): The plaintext password to verify.

    Returns:
        dict: A response indicating success or failure.
            On success: includes status, message, uuid, and username.
            On failure: includes status and error message.
    """
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

def user_exists(user_uuid):
    """
    Checks whether a user exists in the database by UUID.

    Args:
        user_uuid (str): The UUID of the user to check.

    Returns:
        bool: True if the user exists, False otherwise.
    """
    conn = mysql.connector.connect(**DB_CONFIG)
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM users WHERE uuid = %s", (user_uuid,))
    exists = cur.fetchone() is not None
    cur.close()
    conn.close()
    return exists