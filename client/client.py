import os
import sqlite3
from getpass import getpass
from encryption_utils import generate_rsa_keypair, encrypt_private_key, save_key_to_file

DB_PATH = '../server/db/user_db.sqlite'
KEY_DIR = './keys/'

def register_user():
    username = input("Username: ")
    password = getpass("Password: ")

    import hashlib

    # Open DB and check user BED type shyt
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                 username TEXT PRIMARY KEY,
                 salt BLOB,
                 hash BLOB,
                 public_key BLOB)''')

    # Check if user already exists
    c.execute("SELECT * FROM users WHERE username = ?", (username,))
    if c.fetchone():
        print("Username already exists. LOL D:")
        conn.close()
        return

    # Only generate keys after DB check passes 
    priv_key, pub_key = generate_rsa_keypair()

    # Encrypt private key with password
    encrypted_priv_key = encrypt_private_key(priv_key, password.encode())

    # Save the keys locally
    os.makedirs(KEY_DIR, exist_ok=True)
    save_key_to_file(KEY_DIR + f'{username}_public.pem', pub_key)
    save_key_to_file(KEY_DIR + f'{username}_private.enc', encrypted_priv_key)

    # Hash password and store with public key
    salt = os.urandom(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)

    c.execute("INSERT INTO users VALUES (?, ?, ?, ?)", (username, salt, pwd_hash, pub_key))
    conn.commit()
    conn.close()

    print("Registered successfully! :))")

    # === STEP 3: TEST DECRYPTION ===
    from encryption_utils import decrypt_private_key, load_key_from_file
    enc_key = load_key_from_file(KEY_DIR + f'{username}_private.enc')
    decrypted = decrypt_private_key(enc_key, password.encode())
    print("Private key for checking (to remove in final):\n", decrypted[:128])  # Show first 128 bytes

if __name__ == "__main__":
    register_user()
