from .db_config import DB_CONFIG
import mysql.connector

def init_db():
    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor()

    # Create users table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        uuid CHAR(36) UNIQUE NOT NULL,
        username VARCHAR(50) NOT NULL,
        password VARCHAR(255) NOT NULL
    )
    """)

    # Future: Add message table, sessions, groups, etc.
    conn.commit()
    conn.close()
    print("[DB INIT] Database initialized.")
