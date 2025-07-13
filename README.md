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
- Generate TLS certificates (Already Provided for Debugging)
	* Default self-signed TLS certificates are already included in:

```bash

# These are provided for local testing and debugging only.
# If you'd like to generate new self-signed certificates, run:

mkdir -p server/keys
openssl req -newkey rsa:2048 -nodes -keyout server/keys/key.pem -x509 -days 365 -out server/keys/cert.pem
```

## 🧪 Run With Docker 
### 1. Clone the repository

```bash
git clone <your-repo-url>
cd advanced-secure-protocol
docker-compose up --build
```


## 🧪 Run Without Docker (Manual Setup)

If you prefer to run the application without Docker — especially useful when debugging or inspecting protocol behavior — follow these steps:

### 1. Clone the repository

```bash
git clone <your-repo-url>
cd advanced-secure-protocol
```

### 2. Set up a Python virtual environment

```bash
python3 -m venv venv
source venv/bin/activate     # On Windows: venv\Scripts\activate
```
3. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. 🛠️ Database Configuration 
We've included a **separate Docker Compose file** to run only MySQL:

```bash
docker-compose -f docker-compose.mysql.yml up -d
```
This will start a MySQL container using the following credentials:

- Host: `localhost`
- Port: `3306`
- Username: `root`
- Password: `rootpass`
- Database: `chatapp`

You can modify these in the file if needed.

### 4. Update Database Configuration
Update your DB connection settings in: `server/db/db_config.py`
    - Note: The defualt configs are to run the app with docker


### 4. ▶️ Run the App
- After MySQL is running and DB config is set:
```bash
python server/server.py
```
- You're now ready to test, debug, or explore the protocol manually.


# Project Structure
```
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
```
# 🧪 Testing

You can run test client scripts or custom test scripts from the client/ directory.
Ensure both clients connect to the server, log in/register, and securely exchange messages or files.