from .db_config import DB_CONFIG
import mysql.connector

def init_db():
    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            uuid CHAR(36) UNIQUE NOT NULL,
            username VARCHAR(50) NOT NULL,
            password VARCHAR(255) NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS relay_servers (
            id INT AUTO_INCREMENT PRIMARY KEY,
            server_uuid CHAR(36) NOT NULL,
            vpn_ip VARCHAR(15) NOT NULL,
            port INT NOT NULL,
            public_ip VARCHAR(100),
            last_heartbeat TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()
    print("[DB INIT] Database initialized.")
