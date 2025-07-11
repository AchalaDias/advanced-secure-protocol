import time
from ipaddress import IPv4Address

# Base IP range for Group 8: starts at 10.8.0.2
BASE_IP = IPv4Address("10.8.0.2")
MAX_CLIENTS = 65533  # 10.8.0.2 to 10.8.255.254

# Global state (in-memory)
assigned_ips = {}     # uuid -> IP
ip_pool = set()       # All assigned IPs
active_sessions = {}  # uuid -> session info

def assign_ip(user_uuid):
    """Assign a virtual IP address from the pool to a user."""
    if user_uuid in assigned_ips:
        return assigned_ips[user_uuid]

    for i in range(MAX_CLIENTS):
        ip = str(BASE_IP + i)
        if ip not in ip_pool:
            ip_pool.add(ip)
            assigned_ips[user_uuid] = ip
            return ip
    return None  # No available IPs


def release_ip(user_uuid):
    """Release the user's IP back to the pool."""
    ip = assigned_ips.pop(user_uuid, None)
    if ip:
        ip_pool.discard(ip)


def register_session(user_uuid, username, conn, aes_key):
    """Track a user's active session and assign an IP."""
    ip = assign_ip(user_uuid)
    active_sessions[user_uuid] = {
        "conn": conn,
        "ip": ip,
        "username": username,
        "aes_key": aes_key,
        "connected_at": time.time()
    }
    return ip


def remove_session(user_uuid):
    """Remove the user's session on disconnect."""
    active_sessions.pop(user_uuid, None)
    release_ip(user_uuid)


def is_online(user_uuid):
    """Check if a user is currently online."""
    return user_uuid in active_sessions


def get_session(user_uuid):
    """Get full session data for a given user (or None)."""
    return active_sessions.get(user_uuid)

def get_all_sessions():
    """Return all current active sessions."""
    return active_sessions.copy()

def get_session_by_socket(sock):
    """Return sessions by connection."""
    for uuid, session in active_sessions.items():
        if session["conn"] == sock:
            return uuid, session
    return None, None