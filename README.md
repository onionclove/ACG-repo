secure_chat_app/
│
├── client/
│   ├── client.py              # Main client app (sends/receives messages, login GUI)
│   ├── encryption_utils.py    # Encryption logic: AES, RSA, key generation, hashing
│   ├── file_transfer.py       # Logic for encrypting/decrypting and sending images/files
│   ├── gui.py                 # Optional GUI interface 
│   └── keys/
│       ├── user_private.pem   # User's encrypted private RSA key
│       └── user_public.pem    # User's public RSA key
│
├── server/
│   ├── server.py              # Main server: handles user auth, message relaying
│   ├── db/
│   │   └── user_db.sqlite     # SQLite DB for storing user credentials (hashed)
│   └── keys/
│       ├── server_private.pem # Optional: for server-authenticated encryption/signatures
│       └── server_public.pem
│
├── deployment/
│   ├── group_keys/            # (Optional) Shared group keys if group chat is supported
│   └── shared_files/          # Stores uploaded encrypted images/files temporarily
│
├── docs/
│   ├── proposal_report.docx   # Your 10-page report for submission
│   ├── contributions.txt      # Who did what 
│   └── references.bib         # Citations/references if needed
│
├── requirements.txt           # List of dependencies (PyCryptodome, Flask, etc.)
└── README.md                  # GitHub-style documentation

Use these commands nerds:
Installation:
        pip3 install pycryptodome
        pip3 install tk
        pip3 install flask

pip install mysql-connector-python python-dotenv

to enter the GUI:
cd client,
python gui.py

## Expanded guide (based on current code)

### Features
- End-to-end encryption (AES-EAX) with Ed25519 signatures
- Optional PFS per-message (ephemeral X25519 + HKDF)
- Offline delivery queue in MySQL; auto-delivery on return
- Online presence; chat history (ciphertexts in DB, sent plaintext kept locally)
- File transfer: encrypt/sign any file; recipient verifies and decrypts

### Prerequisites
- Python 3.10+
- MySQL 8.x (or compatible)
- Windows: allow Python through Firewall for inbound connections (ephemeral TCP port)

### Virtual environment (For now is Windows PowerShell)
```powershell
```

Install dependencies inside the venv if needed:
```powershell
pip install pycryptodome mysql-connector-python python-dotenv tk
```

### Configure database (.env at repo root)
Create `.env` in the repo root:
```ini
DB_HOST=localhost
DB_PORT=3306
DB_USER=your_mysql_user
DB_PASSWORD=your_mysql_password
DB_DATABASE=acg
```
The app loads this in `client/mysql_wb.py` and will create the database if missing.

### Initialize/reset schema
```powershell
python .\client\init_tables.py --force --seed
```
- `--force`: drop and recreate tables
- `--seed`: add demo users `alice` (Alice$123) and `bob` (Bob$12345) and generate keys in `client/keys/`

### GUI workflow
- Register to generate your keys under `client/keys/`
- Login; presence is published with an ephemeral TCP port
- Select a user; toggle “Use PFS” to enable per-message PFS (default ON)
- Send text/files; offline recipients get queued messages delivered later

### Where things live
- `client/gui.py`: Tkinter UI
- `client/backend.py`: auth, presence, send/receive, pending queue, history
- `client/encryption_utils.py`: ECC (X25519, Ed25519), PBKDF2, AES, sign/verify
- `client/decrypt_messaging.py`: decrypt+verify text (PFS and legacy)
- `client/encrypt_image.py` / `client/decrypt_image.py`: file encrypt/sign and decrypt/verify
- `client/mysql_wb.py`: MySQL connection + schema creation
- `client/init_tables.py`: safe reset/seed tool

### Troubleshooting
- MySQL connectivity: verify `.env` and that MySQL is running
  ```powershell
  python .\client\tests\test_db_conn.py
  ```
- Crypto import errors: ensure venv active and `pycryptodome` installed
- Tkinter missing: install `tk` via pip
- Not receiving messages: allow Python through Windows Firewall

### Notes
- Flask is not required by current code paths
- Private keys are AES-encrypted at rest with PBKDF2-derived keys
- Public signing keys are stored in MySQL for verification

### Credits
See `contributions.txt` for authorship and feature notes.