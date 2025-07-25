from .db_config import DB_CONFIG
import mysql.connector
from protocol.logger import get_logger

logger = get_logger()

# Database schema
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
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS `groups` (
            group_id INT AUTO_INCREMENT PRIMARY KEY,
            group_name VARCHAR(255)
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS `group_members` (
            group_id INT,
            user_uuid VARCHAR(64),
            PRIMARY KEY (group_id, user_uuid),
            FOREIGN KEY (group_id) REFERENCES `groups`(group_id)
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS servers (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(255),
            hostname VARCHAR(255),
            port INT,
            handshake_type VARCHAR(10),
            public_key TEXT,
            username VARCHAR(50),
            password VARCHAR(255),
            user_identifier VARCHAR(255),
            group_identifier VARCHAR(255)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS server_users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            server_id INT,
            user_id VARCHAR(255),
            name VARCHAR(255)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS server_group_messages (
            id INT AUTO_INCREMENT PRIMARY KEY,
            group_id VARCHAR(255),
            user_id VARCHAR(255),
            server_id INT
        )
    """)

    conn.commit()
    conn.close()
    logger.info("[DB INIT] Database initialized.")
