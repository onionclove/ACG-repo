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
Check database for users:
        sqlite3 ../server/db/user_db.sqlite
        .tables
        SELECT username FROM users;
        SELECT * FROM users WHERE username='alice';

Del all users from database (in D:\ACG 25\CA2\ACG-repo\client>)
        del ..\server\db\user_db.sqlite (deletes whole user_db.sqlite file, its created again upon running client.py again use this only for testing reasons)

Installation:
        pip3 install pycryptodome
        pip3 install tk
        pip3 install flask

Jingkai's update:
I implemented a user registration system with RSA key generation and password hashing. Usernames are checked against an SQLite database to prevent duplicates, and passwords are hashed using PBKDF2 with a random salt. A 2048-bit RSA key pair is generated, with the private key encrypted using AES and saved locally. Public keys are stored in the database. The flow make sure keys are only created after validation, and a decryption test confirms successful encryption and key handling.
Implemented a user registration system with X25519 Diffie-Hellman key generation and password hashing. Usernames are checked against an SQLite database to prevent duplicates. Private keys are encrypted using AES and stored locally, with public keys stored in the DB. The system ensures keys are only generated after validation, and includes decryption tests for verification.

Xu Kai's update:
Following Jing Kai's work, I also finished coding up the login and also the message encryption part, encryption use eccdh like we planned. So after me, whoever can do message decryption, encrypt and decrypt images and also digital signature 

Jerome
Message Decryption has been put into fil_transfer.py
For message decryption, two requirements are the receipient's private key and the sender's public key.
typically 64 bytes
nonce = enc_data[:16] "first 16 bytes"
tag = enc_data[16:32] "next 16 bytes"
ciphertext = enc_data[32:] "rest of the bytes"
It:
Accepts the recipient's private key, sender's public key, and the base64-encoded nonce, tag, and ciphertext.
Derives the shared AES key using ECDH.
Decodes and concatenates the encrypted components.