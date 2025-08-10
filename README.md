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

Testing Encryption (in terminal):
        cd client (cd into client first)
        python client.py (to choose between registration and login)
        register name and password
        login with name and password
        given prompt to send message to, enter name you want to send to
        then enter the message

Testing Decryption (in terminal):
        cd client (cd into client first)
        python decrypt_messaging.py
        prompted for Recipient's username
        prompted for Sender's username
        prompted for Recipient's password
        prompted for Nonce (base64)
        prompted for Tag (base64)
        prompted for Ciphertext (base64)
        Decrypted message will then be displayed

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

Craig
Inplemented Image encryption and decryption in encrypt_image.py and decrypt_image.py.
2 requirements are receiver private key and sender public key for decryption and receiver public key and sender private key for encryption. Use by running python encrypt_image or python decrypt_image for either encryption or decryption of image.




Jotish: Implemented end-to-end message and image authentication via digital signatures. Extended the existing key system by adding an Ed25519 signing keypair per user (private key encrypted with user password, public key stored in the user database) alongside the existing X25519/ECC key agreement keys. Modified the send and receive flows 
To:
Sign the encrypted payload (nonce || tag || ciphertext) with the sender’s Ed25519 private key, producing a signature that is transmitted/appended.
Verify that signature on the recipient side using the sender’s signing public key before attempting decryption.
This ensures the recipient can trust who sent the message or image and that it wasn’t altered in transit, while preserving confidentiality through the existing ECDH+AES encryption. Added safe fallback logic for key material types, handled blob construction correctly, and enforced abort-on-signature-failure to prevent tampered data from being processed.

Jotish: Made it so that users don't need to manually insert the ip and port of the user they want to contact, backend automatically scans and resolves them. Logged in users also dynamically get assigned a port upon each login. 


Jerome & Craig: We added offline_users into the database so that we are able to differentiate between who is offline and online.

We also added a log-out feature where the user is made offline, and the GUI gets rid of the texts and chat list. 

We edited the GUI so that we are able to see a list of who is texting who, albeit there not being a history, however that is Xu Kai's part.

There was also an error where we could not text people that were offline as online users, which was fixed by adding a pending_messages database where messages can be sent in advance. Messages sent in advance are then delivered to that user once they are logged in.

pip install mysql-connector-python python-dotenv

Jotish: Pending messages in both PFS on and off now get sent. When the user reads their pending messages, they get deleted from the table and get sent to the messages table that shows all officially sent messages.
GUI now displays ALL online and offline users in the chats column, logged out/unregistered users can also view this list. Dynamically updated every 3 seconds.

Xu Kai: chat history code are in backend.py, client.py, mysql_wb.py and created file history.py cant test yet login problem whoever can login tell me i tell yall how to test