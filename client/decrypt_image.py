import os
import sqlite3
from encryption_utils import (
    import_key, decrypt_private_key, load_key_from_file, verify_blob
)
from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

DB_PATH = '../server/db/user_db.sqlite'

def decrypt_and_verify_image(
    priv_key_path,
    password,
    sender_pub_key_path,
    encrypted_image_path,
    output_path,
    sender_username
):
    if not os.path.exists(encrypted_image_path):
        raise FileNotFoundError(f"Encrypted image file not found: {encrypted_image_path}")

    try:
        encrypted_key = load_key_from_file(priv_key_path)
        decrypted_key = decrypt_private_key(encrypted_key, password.encode())
        recipient_priv_key = ECC.import_key(decrypted_key)
    except Exception as e:
        raise RuntimeError(f"Failed to decrypt your exchange private key: {e}")

    try:
        with open(sender_pub_key_path, 'rt') as f:
            sender_exchange_pub = ECC.import_key(f.read())
    except Exception as e:
        raise RuntimeError(f"Failed to load sender's exchange public key: {e}")

    try:
        data = open(encrypted_image_path, 'rb').read()
        if len(data) < 96:
            raise ValueError("File too short to contain nonce, tag, ciphertext, and signature.")
        nonce = data[:16]
        tag = data[16:32]
        signature = data[-64:]
        ciphertext = data[32:-64]
    except Exception as e:
        raise RuntimeError(f"Failed to parse encrypted image file: {e}")

    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT signing_public_key FROM users WHERE username = ?", (sender_username,))
        row = c.fetchone()
        conn.close()
        if not row or row[0] is None:
            raise ValueError("Sender's signing public key missing in DB.")
        signing_pub_pem = row[0]
        if isinstance(signing_pub_pem, memoryview):
            signing_pub_pem = signing_pub_pem.tobytes()
    except Exception as e:
        raise RuntimeError(f"Failed to fetch signing public key from DB: {e}")

    to_verify = nonce + tag + ciphertext
    if not verify_blob(signing_pub_pem, to_verify, signature):
        raise ValueError("Signature invalid. Aborting decryption.")

    try:
        shared_point = sender_exchange_pub.pointQ * recipient_priv_key.d
        shared_secret = int(shared_point.x).to_bytes(32, 'big')
        aes_key = SHA256.new(shared_secret).digest()
    except Exception as e:
        raise RuntimeError(f"Failed to derive shared key: {e}")

    try:
        cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        with open(output_path, 'wb') as f:
            f.write(plaintext)
        return True
    except Exception as e:
        raise RuntimeError(f"Decryption/authentication failed: {e}")
