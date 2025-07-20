from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import base64
import sqlite3
DB_PATH = '../server/db/user_db.sqlite'

def send_encrypted_message(recipient_username, plaintext_msg):
    # === Load recipient's public key from DB ===
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT public_key FROM users WHERE username = ?", (recipient_username,))
    row = c.fetchone()
    conn.close()

    if not row:
        print("Recipient not found.")
        return

    recipient_pub_key_pem = row[0]
    recipient_pub_key = RSA.import_key(recipient_pub_key_pem)

    # === Step 1: Generate AES session key ===
    aes_key = get_random_bytes(16)  # 128-bit AES

    # === Step 2: Encrypt the message using AES ===
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext_msg.encode())

    # === Step 3: Encrypt the AES key with recipient's RSA public key ===
    cipher_rsa = PKCS1_OAEP.new(recipient_pub_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)

    # === Simulate sending: print or return encoded values ===
    print("\nEncrypted message ready to send:")
    print("Encrypted AES key (base64):", base64.b64encode(encrypted_aes_key).decode())
    print("Nonce (base64):", base64.b64encode(cipher_aes.nonce).decode())
    print("Tag (base64):", base64.b64encode(tag).decode())
    print("Ciphertext (base64):", base64.b64encode(ciphertext).decode())
