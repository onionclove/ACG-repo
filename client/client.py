import os
import sqlite3
import base64
import hashlib
from encryption_utils import (
    generate_dh_keypair, export_key, encrypt_private_key, save_key_to_file,
    decrypt_private_key, load_key_from_file, sign_blob
)
from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

DB_PATH = '../server/db/user_db.sqlite'
KEY_DIR = './keys/'

def register_user(username, password):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Create users table (permanent info)
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        salt BLOB,
        hash BLOB,
        public_key BLOB,
        signing_public_key BLOB
    )''')

    # Create online_users table (session info)
    c.execute('''CREATE TABLE IF NOT EXISTS online_users (
        username TEXT PRIMARY KEY,
        ip_address TEXT NOT NULL,
        port INTEGER NOT NULL,
        updated_on TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')

    # Check if user already exists
    c.execute("SELECT * FROM users WHERE username = ?", (username,))
    if c.fetchone():
        conn.close()
        raise ValueError("Username already exists.")

    # Generate keys
    priv_key, pub_key = generate_dh_keypair()
    priv_key_pem = export_key(priv_key).encode()
    pub_key_pem = export_key(pub_key).encode()
    encrypted_priv_key = encrypt_private_key(priv_key_pem, password.encode())

    sign_priv = ECC.generate(curve='Ed25519')
    sign_pub = sign_priv.public_key()
    sign_priv_pem = sign_priv.export_key(format='PEM').encode()
    sign_pub_pem = sign_pub.export_key(format='PEM').encode()
    encrypted_sign_priv = encrypt_private_key(sign_priv_pem, password.encode())

    # Save keys to files
    os.makedirs(KEY_DIR, exist_ok=True)
    save_key_to_file(KEY_DIR + f'{username}_public.pem', pub_key_pem)
    save_key_to_file(KEY_DIR + f'{username}_private.enc', encrypted_priv_key)
    save_key_to_file(KEY_DIR + f'{username}_signing_private.enc', encrypted_sign_priv)

    # Hash password
    salt = os.urandom(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)

    # Store user info in DB
    c.execute("INSERT INTO users (username, salt, hash, public_key, signing_public_key) VALUES (?, ?, ?, ?, ?)",
              (username, salt, pwd_hash, pub_key_pem, sign_pub_pem))

    conn.commit()
    conn.close()
    return True

def login_user(username, password, ip_address, port):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Verify password
    c.execute("SELECT salt, hash FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    if not row:
        conn.close()
        raise ValueError("User not found.")
    salt, stored_hash = row
    test_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    if test_hash != stored_hash:
        conn.close()
        raise ValueError("Incorrect password.")

    # Store IP and port in online_users table
    c.execute('''INSERT OR REPLACE INTO online_users (username, ip_address, port)
                 VALUES (?, ?, ?)''', (username, ip_address, port))
    conn.commit()
    conn.close()

    # Load decrypted private key
    enc_key_path = os.path.join(KEY_DIR, f"{username}_private.enc")
    encrypted_key = load_key_from_file(enc_key_path)
    decrypted_key = decrypt_private_key(encrypted_key, password.encode())
    return decrypted_key

def send_encrypted_message(sender_username, password, recipient_username, message):
    encrypted_priv = load_key_from_file(f"./keys/{sender_username}_private.enc")
    priv_key_pem = decrypt_private_key(encrypted_priv, password.encode())
    sender_priv_key = ECC.import_key(priv_key_pem)

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Get recipient's key and IP/port from both tables
    c.execute("SELECT public_key FROM users WHERE username = ?", (recipient_username,))
    user_row = c.fetchone()

    c.execute("SELECT ip_address, port FROM online_users WHERE username = ?", (recipient_username,))
    net_row = c.fetchone()

    conn.close()

    if not user_row or not net_row:
        raise ValueError("Recipient not found or offline.")

    recipient_pub_pem = user_row[0]
    if isinstance(recipient_pub_pem, memoryview):
        recipient_pub_pem = recipient_pub_pem.tobytes()
    recipient_pub_key = ECC.import_key(recipient_pub_pem)

    recipient_ip, recipient_port = net_row

    shared_secret = sender_priv_key.d * recipient_pub_key.pointQ
    shared_secret_bytes = int(shared_secret.x).to_bytes(32, byteorder='big')
    aes_key = SHA256.new(shared_secret_bytes).digest()

    cipher = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    nonce = cipher.nonce
    to_sign = nonce + tag + ciphertext

    signing_priv_enc = load_key_from_file(f"./keys/{sender_username}_signing_private.enc")
    signing_priv_pem = decrypt_private_key(signing_priv_enc, password.encode())
    signature = sign_blob(signing_priv_pem, to_sign)

    return {
        "nonce": base64.b64encode(nonce).decode(),
        "tag": base64.b64encode(tag).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "signature": base64.b64encode(signature).decode(),
        "recipient_ip": recipient_ip,
        "recipient_port": recipient_port
    }
