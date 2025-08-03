import base64
import sqlite3
from encryption_utils import (
    import_key, decrypt_private_key, load_key_from_file, verify_blob
)
from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

DB_PATH = '../server/db/user_db.sqlite'

def decrypt_and_verify_message(
    priv_key_path,
    password,
    sender_pub_key_path,
    nonce_b64,
    tag_b64,
    ciphertext_b64,
    signature_b64,
    sender_username
):
    try:
        encrypted_key = load_key_from_file(priv_key_path)
        decrypted_key = decrypt_private_key(encrypted_key, password.encode())
        recipient_priv_key = ECC.import_key(decrypted_key)
    except Exception as e:
        raise RuntimeError(f"Failed to decrypt your private key: {e}")

    try:
        with open(sender_pub_key_path, 'rt') as f:
            sender_pub_key = ECC.import_key(f.read())
    except Exception as e:
        raise RuntimeError(f"Failed to load sender's public key: {e}")

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
        raise RuntimeError(f"Failed to fetch signing public key: {e}")

    try:
        nonce = base64.b64decode(nonce_b64)
        tag = base64.b64decode(tag_b64)
        ciphertext = base64.b64decode(ciphertext_b64)
        signature = base64.b64decode(signature_b64)
        to_verify = nonce + tag + ciphertext

        if not verify_blob(signing_pub_pem, to_verify, signature):
            raise ValueError("Signature invalid. Aborting decryption.")
    except Exception as e:
        raise RuntimeError(f"Verification failed: {e}")

    try:
        shared_point = sender_pub_key.pointQ * recipient_priv_key.d
        shared_secret = int(shared_point.x).to_bytes(32, 'big')
        aes_key = SHA256.new(shared_secret).digest()
        cipher = AES.new(aes_key, AES.MODE_EAX, nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode()
    except Exception as e:
        raise RuntimeError(f"Decryption failed: {e}")
