
# Secure Chat Protocol Server

This is a secure chat server built using Python and TLS-encrypted sockets. It supports user-to-user messaging, group chat, and secure file transfer. The system ensures confidentiality, integrity, and authentication using modern cryptographic protocols.

---

## Group Name & Members
- Group Name: Group Project 8
- Anthonan Hettige Achala Tharaka Dias (a1933508)
- Sanjida Amrin (a1934493)
- Zahin Rydha (a1938252)

## 🚀 Features

-   🔒  **TLS-encrypted TCP communication**  for secure client-server and server-server channels
    
-   🔐  **RSA-based session key exchange**  followed by AES-GCM for message confidentiality and integrity
    
-   👤  **User registration and login**  with hashed passwords (`bcrypt`)
    
-   💡  **Session management and virtual IP assignment**  for user tracking and presence
    
-   💬  **Real-time messaging**  between individual users and user groups
    
-   🌐  **Online user discovery**  across all connected servers
    
-   👥  **Group messaging**  with dynamic group creation, listing, and membership management
    
-   📂  **Secure file transfer**  (AES-GCM encrypted) with extension whitelisting and size limit (≤ 5MB)
    
-   🛰️  **Server-to-server communication**  with secure handshake (auto/manual), authentication, and remote user mapping
    
-   🔁  **Inter-server message forwarding**  for users and groups, allowing cross-network communication
    
-   🧾  **MySQL-based persistent backend**  for users, groups, and registered peer servers
    
-   📄  **Structured logging**  to both console and  `server.log`  for debugging and auditability
      

---

# Project Structure

```

advanced-secure-protocol/

│

├── server/

│ ├── db/ # MySQL DB config and schema

│ ├── keys/ # TLS certificates

│ ├── protocol/ # Core protocol handlers

│ ├── server.py # Main TLS socket server

│ └── Dockerfile # Docker configuration for server

│

├── clients/ # Example test clients

│

├── docker-compose.yml # Docker Compose configuration

├── docker-compose.mysql.yml # Docker Compose file for local mysql db

└── README.md

```

  

### Prerequisites

  

- Docker

- Docker Compose

- Generate TLS certificates (Already Provided for Debugging)

* Default self-signed TLS certificates are already included in:

  

```bash

  

# These are provided for local testing and debugging only.

# If you'd like to generate new self-signed certificates, run:

  

mkdir  -p  server/keys

openssl  req  -newkey  rsa:2048  -nodes  -keyout  server/keys/key.pem  -x509  -days  365  -out  server/keys/cert.pem

```

  

## 🐳 Run With Docker

### 1. Clone the repository

  

```bash

git  clone <your-repo-url>

cd  advanced-secure-protocol

docker-compose  up  --build

```

  
  

## 🧪 Run Without Docker (Manual Setup)

  

If you prefer to run the application without Docker — especially useful when debugging or inspecting protocol behavior — follow these steps:

  

### 1. Clone the repository

  

```bash

git  clone <your-repo-url>

cd  advanced-secure-protocol

```

  

### 2. Set up a Python virtual environment

  

```bash

python3  -m  venv  venv

source  venv/bin/activate  # On Windows: venv\Scripts\activate

```

3. Install dependencies

```bash

pip  install  -r  requirements.txt

```

  

### 3. 🛠️ Database Configuration

We've included a **separate Docker Compose file** to run only MySQL:

  

```bash

docker-compose  -f  docker-compose.mysql.yml  up  -d

```

This will start a MySQL container using the following credentials:

  

- Host: `localhost`

- Port: `3306`

- Username: `root`

- Password: `rootpass`

- Database: `chatapp`

  

You can modify these in the file if needed.
DB Config file location: `server/db/db_config.py`

  

###  4. Update Database Configuration

Update your DB connection settings in: `server/db/db_config.py`

- Note: The defualt configs are to run the app with docker

  
  

###  5. ▶️ Run the App

- After MySQL is running and DB config is set:

```bash

python  server/server.py

```

- You're now ready to test, debug, or explore the protocol manually.

  

# 🧪 Testing

  

You can run test client scripts or custom test scripts from the client/ directory.

Ensure both clients connect to the server, log in/register, and securely exchange messages or files.

You can run multiple client scripts in different terminals to simulate different users. The following scenarios are supported and tested:

  

### 1. User to User Message passing

```bash

python  clients/client_message.py

```

- Step 1: Start Client A

- Enter r to register, then:

```bash

Username: alice

Password: Alice@123

```

- Step 2: Start Client B

- Enter r to register, then:

```bash

Username: bob

Password: Bob@1234

```

- ✅ You can also choose `l` to log in with an existing user.

  

- After login, the client will:

- Request the list of online users.

- Display all users with their uuid, username, and ip.

- From Client A, select Bob’s uuid

Type a message:

```bash

Send  to  user  UUID: <bob's uuid>

Enter message: Hello Bob!

```

- From Client B

Bob will receive Alice’s message in real time in his terminal.

Repeat to simulate chat between users.

  
  

### 2. User to Group Message passing

```bash

python  clients/group_message.py

```

  

- Step 1: Login as Alice

- After login, choose to:

- Create a group (e.g. "team")

- Add Bob’s UUID to the group

  

- Step 2: From Alice’s client

- Send a group message to group ID (e.g. 1):

- Send to user UUID: 1

Enter message: Hello team!

- Step 3: From Bob’s client

  

- Bob (if online and in group) receives the message.

- 🧪 You can add more users to the group and repeat the test.

  

###  3. File Transfering Message passing

```bash

python  clients/file_transfer.py

```

Files larger than 10MB will be automatically rejected by the server.

  

- Step 1: From Alice's client

- After login and AES key exchange, choose a file to send:

```bash

Send to (user/group): user or gorup

Enter UUID (user) or Group ID (group): <bob's uuid> or <gorup ID>

Path to file: /path/to/testfile.pdf

```

- The file will be encrypted, sent to the server, and forwarded to Bob.

- Step 2: From Bob’s client

- The file will be saved with the original filename in the local directory.

Same applies for group file transfer using the group ID instead of user UUID.


### 4. Running the Test Suite - Unit Tests

To run all tests from the project root:
```
 python -m pytest -vv 

```
That’s it — no server or database needs to be running.
The test suite uses stubs and mocks to simulate connections, encryption, and database calls.


# 📁 Project Structure Overview & Implementation Details

This section outlines the role of each file and directory in the `advanced-secure-protocol` project.

🔹 Root Directory

```advanced-secure-protocol/
├── clients/
├── server/
├── docker-compose.yml
├── docker-compose.mysql.yml
├── README.md
```

-   **clients/**  – Example clients for messaging, file transfer, and group communication.
    
-   **server/**  – Backend server including protocol logic, database, and encryption handling.
    
-   **docker-compose.yml**  – Launches chat server and MySQL together.
    
-   **docker-compose.mysql.yml**  – Optional MySQL-only Compose file.
    
-   **README.md**  – Project documentation and usage instructions.

----------
### 🧪  `clients/`  – Test Clients

```
clients/
├── client_message.py     # Sends private user-to-user messages securely
├── group_message.py      # Sends secure group messages
├── file_transfer.py      # Uploads and downloads files using AES encryption
├── tt.txt                # Sample test file used in file transfer` 
```
-   `client_message.py`  – CLI tool for sending encrypted private messages.
    
-   `group_message.py`  – Used to send encrypted messages to groups.
    
-   `file_transfer.py`  – Secure file transfer (to user or group) using AES-GCM.
    
-   `tt.txt`  – Test file for verifying file transfer functionality.
    
----------

### 🧠  `server/`  – Main Server Code
```
server/
├── db/                   # Database models and initialization scripts
├── keys/                 # TLS certificate and key files
├── protocol/             # Core protocol logic (crypto, sessions, handlers)
├── server.py             # Main TLS-secured chat server
├── Dockerfile            # Container definition for chat server
├── requirements.txt      # Python dependencies
├── server.log            # Runtime logs of the chat server` 
```
-   `server.py`  – Entry point for the TLS-enabled socket server.
    
-   `Dockerfile`  – Builds the server container image.
    
-   `requirements.txt`  – Lists Python dependencies.
    
-   `server.log`  – Log file used for debugging and auditing.

-----

### 🗄️  `server/db/`  – Database Layer
```
server/db/
├── db_config.py          # MySQL connection details
├── db_init.py            # Creates users, groups, and server tables
├── user_model.py         # Handles user authentication and registration
├── group_model.py        # Group creation and membership logic
├── server_model.py       # Remote server and user mapping logic` 
```
-   Used for interacting with the MySQL database (users, groups, and servers).

----

### 🔐  `server/protocol/`  – Secure Communication Protocol Core

```
server/protocol/
├── connection_handler.py  # Manages TLS connections and incoming message routing
├── crypto.py              # Handles key generation, encryption, and decryption (RSA & AES-GCM)
├── handler.py             # Main processor for message types like user, group, and file messages
├── server_link.py         # Establishes and manages secure connections with other chat servers
├── session_manager.py     # Tracks all active user and server sessions, assigns virtual IPs
├── logger.py              # Central logging setup used across the server` 
```
-   **`connection_handler.py`**  – The main entry point for new client connections. Handles TLS socket wrapping, key exchange (RSA + AES), and dispatches decrypted messages to appropriate handlers.
    
-   **`crypto.py`**  – Provides cryptographic utilities, including RSA key generation, AES-GCM encryption/decryption, and secure random key generation. Ensures message confidentiality and integrity.
    
-   **`handler.py`**  – Core router for incoming protocol messages. Determines whether a message is a private message, group message, or file transfer, and triggers the appropriate logic securely.
    
-   **`server_link.py`**  – Enables server-to-server communication. Responsible for connecting to peer servers, performing handshake (auto/manual), exchanging messages across networks, and routing inter-server traffic.
    
-   **`session_manager.py`**  – Maintains in-memory session state for all users and peer servers. Handles user IP assignment, active socket connections, AES key tracking, and presence (online/offline) management.
    
-   **`logger.py`**  – Centralized logger used throughout the application. Logs server activity, errors, and important events into  `server.log`  for debugging and audit purposes.



