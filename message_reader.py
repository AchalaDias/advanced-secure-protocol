## Group Name & Members
# - Group Name: Group Project 8
# - Anthonan Hettige Achala Tharaka Dias (a1933508)
# - Sanjida Amrin (a1934493)
# - Zahin Rydha (a1938252)

import base64
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# AES key (hex -> bytes)
aes_key_hex = "653bfd8b20d1d3f043160bc6413537501f3bdebed09590c1ae1891ff216165c3"
aes_key = bytes.fromhex(aes_key_hex)

# Your sample log record (as if read from .msglog)
log_entry = {
    "timestamp": "2025-07-24T08:33:27.473798Z",
    "sender_name": "achala",
    "sender_uuid": "e33dc7a3-35cf-4fa4-b16e-a6d96d6cdd3e",
    "payload": "4VF+odhJQDycgzFDtw+1tucyZjBnlNM/KSDSGAqkXinrL92d53gktB8L3KeMHF9YnMkqSGKa2FK+pAAY9noQea2zO4L8BiX/Q9tGRVsHjP4N46W1ydK/OJOidiNoLUWxGQUdAnzwFkg0j8pn03DAYnN1neBB9rkDtu7Ss77M94pM+N+9oCLjt7Kw5ysHRVdMVYKZPtYpK5/xgoaj2VOMJM7JWU20Dhb11+riPfnjeQt7TLaCOKWJlPmg1j/PSeRweBVbzgOt95Mox4eEjcs7cbLRCNIeXMi8E6QyEz8QkaiNuBBBL7aq7FY="
}

# Decrypt the payload
def decrypt_payload(payload_b64: str, aes_key: bytes) -> dict:
    try:
        encrypted_data = base64.b64decode(payload_b64)
        iv = encrypted_data[:12]  # AESGCM standard IV length
        ciphertext = encrypted_data[12:]
        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(iv, ciphertext, None)
        return json.loads(plaintext.decode())
    except Exception as e:
        print(f"Decryption failed: {e}")
        return None

# Run decryption
decrypted_message = decrypt_payload(log_entry["payload"], aes_key)

# Display result
if decrypted_message:
    print(f"[{log_entry['timestamp']}] From: {log_entry['sender_name']} ({log_entry['sender_uuid']})")
    print(json.dumps(decrypted_message, indent=4))
else:
    print("Failed to decrypt the message.")
