import os
import sqlite3
from getpass import getpass
from encryption_utils import generate_dh_keypair, export_key, encrypt_private_key, save_key_to_file

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
    priv_key, pub_key = generate_dh_keypair()
    priv_key_pem = export_key(priv_key).encode()
    pub_key_pem = export_key(pub_key).encode()

    # Encrypt private key with password
    encrypted_priv_key = encrypt_private_key(priv_key_pem, password.encode())

    # Save the keys
    os.makedirs(KEY_DIR, exist_ok=True)
    save_key_to_file(KEY_DIR + f'{username}_public.pem', pub_key_pem)
    save_key_to_file(KEY_DIR + f'{username}_private.enc', encrypted_priv_key)

    # Hash password and store with public key
    salt = os.urandom(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)

    c.execute("INSERT INTO users VALUES (?, ?, ?, ?)", (username, salt, pwd_hash, pub_key_pem))
    conn.commit()
    conn.close()

    print("Registered successfully! :))")

    # === STEP 3: TEST DECRYPTION ===
    from encryption_utils import decrypt_private_key, load_key_from_file
    enc_key = load_key_from_file(KEY_DIR + f'{username}_private.enc')
    decrypted = decrypt_private_key(enc_key, password.encode())
    print("Private key for checking (to remove in final):\n", decrypted[:128])  # Show first 128 bytes

def login_user():
    username = input("Username: ")
    from getpass import getpass
    password = getpass("Password: ")

    import hashlib
    from encryption_utils import decrypt_private_key, load_key_from_file
    import os
    import sqlite3

    # Open DB connection
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Fetch user record
    c.execute("SELECT salt, hash FROM users WHERE username = ?", (username,))
    row = c.fetchone()

    if not row:
        print("No such user.")
        conn.close()
        return None, None, None

    salt, stored_hash = row

    # Hash input password using stored salt
    test_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)

    # Verify password
    if test_hash != stored_hash:
        print("Incorrect password.")
        conn.close()
        return None, None, None

    # Try to decrypt private key
    enc_key_path = os.path.join(KEY_DIR, f"{username}_private.enc")
    if not os.path.exists(enc_key_path):
        print("Encrypted private key file not found.")
        return None, None, None

    try:
        encrypted_key = load_key_from_file(enc_key_path)
        decrypted_key = decrypt_private_key(encrypted_key, password.encode())

        print("Login successful! 🔐")
        print("Private key loaded (partial):\n", decrypted_key[:128])

        return username, password, decrypted_key

    except Exception as e:
        print("Error decrypting private key:", e)
        return None, None, None

def send_encrypted_message(sender_username, password, recipient_username, message):
    from encryption_utils import decrypt_private_key, load_key_from_file
    from Crypto.Cipher import AES
    from Crypto.Hash import SHA256
    from Crypto.PublicKey import ECC
    from Crypto.Random import get_random_bytes
    import base64
    import sqlite3

    # === Load sender's encrypted private key ===
    priv_key_path = f"./keys/{sender_username}_private.enc"
    encrypted_priv = load_key_from_file(priv_key_path)
    priv_key_pem = decrypt_private_key(encrypted_priv, password.encode())
    sender_priv_key = ECC.import_key(priv_key_pem)

    # === Load recipient's public key from DB ===
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT public_key FROM users WHERE username = ?", (recipient_username,))
    row = c.fetchone()
    conn.close()

    if not row:
        print("Recipient not found.")
        return

    recipient_pub_pem = row[0]
    if isinstance(recipient_pub_pem, memoryview):
        recipient_pub_pem = recipient_pub_pem.tobytes()
    recipient_pub_key = ECC.import_key(recipient_pub_pem)

    # === Derive shared secret ===
    shared_secret = sender_priv_key.d * recipient_pub_key.pointQ
    shared_secret_bytes = int(shared_secret.x).to_bytes(32, byteorder='big')

    # === Derive AES key from shared secret ===
    aes_key = SHA256.new(shared_secret_bytes).digest()

    # === Encrypt the message ===
    cipher = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())

    # === Print values to simulate sending ===
    print("\nEncrypted ECC message:")
    print("Nonce:", base64.b64encode(cipher.nonce).decode())
    print("Tag:", base64.b64encode(tag).decode())
    print("Ciphertext:", base64.b64encode(ciphertext).decode())

if __name__ == "__main__":
    choice = input("Type 'r' to register, 'l' to login: ").lower()

    if choice == 'r':
        register_user()

    elif choice == 'l':
        result = login_user()
        if not result or result[0] is None:
            exit()

        username, password, decrypted_key = result

        # Prompt for messaging
        to_user = input("Send message to: ")
        msg = input("Message to encrypt: ")
        send_encrypted_message(username, password, to_user, msg)

    else:
        print("Invalid option.")