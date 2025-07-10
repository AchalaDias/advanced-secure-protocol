import mysql.connector
from db.db_config import DB_CONFIG

def create_group(group_name):
    conn = mysql.connector.connect(**DB_CONFIG)
    cur = conn.cursor()
    cur.execute("INSERT INTO `groups` (group_name) VALUES (%s)", (group_name,))
    group_id = cur.lastrowid
    conn.commit()
    cur.close()
    conn.close()
    return group_id

def add_user_to_group(group_id, user_uuid):
    conn = mysql.connector.connect(**DB_CONFIG)
    cur = conn.cursor()
    cur.execute("INSERT IGNORE INTO group_members (group_id, user_uuid) VALUES (%s, %s)", (group_id, user_uuid))
    conn.commit()
    cur.close()
    conn.close()

def get_group_members(group_id):
    conn = mysql.connector.connect(**DB_CONFIG)
    cur = conn.cursor()
    cur.execute("SELECT user_uuid FROM group_members WHERE group_id = %s", (group_id,))
    members = [row[0] for row in cur.fetchall()]
    cur.close()
    conn.close()
    return members

def get_groups_by_user(user_uuid):
    conn = mysql.connector.connect(**DB_CONFIG)
    cur = conn.cursor()
    cur.execute("""
        SELECT g.group_id, g.group_name
        FROM `groups` g
        JOIN group_members m ON g.group_id = m.group_id
        WHERE m.user_uuid = %s
    """, (user_uuid,))
    groups = [{"group_id": row[0], "group_name": row[1]} for row in cur.fetchall()]
    cur.close()
    conn.close()
    return groups
