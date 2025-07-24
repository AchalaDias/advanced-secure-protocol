import mysql.connector
from db.db_config import DB_CONFIG

def get_db_conn():
    """ Initializing the db connection """
    return mysql.connector.connect(**DB_CONFIG)

def create_group(group_name):
    """
    Creates a new group in the database.

    Args:
        group_name (str): The name of the group to create.

    Returns:
        int: The ID of the newly created group.
    """
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("INSERT INTO `groups` (group_name) VALUES (%s)", (group_name,))
    group_id = cur.lastrowid
    conn.commit()
    cur.close()
    conn.close()
    return group_id

def add_user_to_group(group_id, user_uuid):
    """
    Adds a user to a group in the database.

    Args:
        group_id (int): The ID of the group.
        user_uuid (str): The UUID of the user to add.
    """
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("INSERT IGNORE INTO group_members (group_id, user_uuid) VALUES (%s, %s)", (group_id, user_uuid))
    conn.commit()
    cur.close()
    conn.close()

def get_group_members(group_id):
    """
    Retrieves all user UUIDs belonging to a specific group.

    Args:
        group_id (int): The ID of the group.

    Returns:
        list: A list of user UUIDs who are members of the group.
    """
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("SELECT user_uuid FROM group_members WHERE group_id = %s", (group_id,))
    members = [row[0] for row in cur.fetchall()]
    cur.close()
    conn.close()
    return members

def get_groups_by_user(user_uuid):
    """
    Retrieves all groups that a user is a member of.

    Args:
        user_uuid (str): The UUID of the user.

    Returns:
        list: A list of dictionaries, each containing 'group_id' and 'group_name'.
    """
    conn = get_db_conn()
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

def get_group_name_by_id(group_id):
    """
    Retrieves the name of a group given its group ID.

    Args:
        group_id (int): The ID of the group.

    Returns:
        str or None: The name of the group, or None if not found.
    """
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("SELECT group_name FROM `groups` WHERE group_id = %s", (group_id,))
    result = cur.fetchone()
    cur.close()
    conn.close()
    return result[0] if result else None

