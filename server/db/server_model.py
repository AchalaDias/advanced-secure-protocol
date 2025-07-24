import mysql.connector
import uuid
from .db_config import DB_CONFIG

def get_db_conn():
    """ Initializing the db connection """
    return mysql.connector.connect(**DB_CONFIG)

def fetch_all_servers():
    conn = get_db_conn()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM servers")
    servers = cursor.fetchall()
    conn.close()
    return servers

def save_server_users(server_id, users):
    """
    Insert or update the list of online users from a remote server.
    Clears previous entries for the server first.

    Args:
        server_id (int): The ID of the server.
        users (list): List of dicts with 'uuid' and 'username'.
    """
    conn = get_db_conn()
    cursor = conn.cursor()

    # Clear previous entries for this server
    cursor.execute("DELETE FROM server_users WHERE server_id = %s", (server_id,))

    # Insert new users
    for user in users:
        cursor.execute(
            "INSERT INTO server_users (server_id, user_id, name) VALUES (%s, %s, %s)",
            (server_id, user["user_id"], user["name"])
        )

    conn.commit()
    conn.close()