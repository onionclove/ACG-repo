from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import base64
import sqlite3

DB_PATH = '../server/db/user_db.sqlite'

def rsa_encrypt_message(recipient_username, plaintext_msg):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT public_key FROM users WHERE username = ?", (recipient_username,))
    row = c.fetchone()
    conn.close()

    if not row:
        raise ValueError("Recipient not found.")

    recipient_pub_key_pem = row[0]
    recipient_pub_key = RSA.import_key(recipient_pub_key_pem)

    aes_key = get_random_bytes(16)  # 128-bit AES
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext_msg.encode())

    cipher_rsa = PKCS1_OAEP.new(recipient_pub_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)

    return {
        "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode(),
        "nonce": base64.b64encode(cipher_aes.nonce).decode(),
        "tag": base64.b64encode(tag).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }
