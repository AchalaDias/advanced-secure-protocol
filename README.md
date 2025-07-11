# Advanced Secure Protocol

# Secure Chat Protocol Server

This is a secure chat server built using Python and TLS-encrypted sockets. It supports user-to-user messaging, group chat, and secure file transfer. The system ensures confidentiality, integrity, and authentication using modern cryptographic protocols.

---

## 🚀 Features

- TLS-encrypted TCP communication
- Secure AES-GCM encrypted payloads
- RSA-based key exchange
- User registration and login
- Session management and user presence
- Real-time messaging (individual and group)
- Secure file transfer with size limit (≤10MB)
- Group creation, listing, membership, and broadcasting
- Online user discovery
- Logging to file and console

---

## 🐳 Docker Setup

### Prerequisites

- Docker
- Docker Compose

### 1. Clone the repository

```bash
git clone <your-repo-url>
cd advanced-secure-protocol
docker-compose up --build
```
# Project Structure

advanced-secure-protocol/
│
├── server/
│   ├── db/                  # MySQL DB config and schema
│   ├── keys/                # TLS certificates
│   ├── protocol/            # Core protocol handlers
│   ├── server.py            # Main TLS socket server
│   └── Dockerfile
│
├── clients/                  # Example test clients
│
├── docker-compose.yml       # Docker Compose configuration
└── README.md

# 🧪 Testing

You can run test client scripts or custom test scripts from the client/ directory.
Ensure both clients connect to the server, log in/register, and securely exchange messages or files.