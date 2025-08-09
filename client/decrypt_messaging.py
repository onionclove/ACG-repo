# decrypt_messaging.py (MySQL version)
import base64
from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

from encryption_utils import decrypt_private_key, import_key, verify_blob
from mysql_wb import get_conn, q

def decrypt_and_verify_message(
    priv_key_path: str,
    password: str,
    sender_pub_key_path: str,
    nonce_b64: str,
    tag_b64: str,
    ciphertext_b64: str,
    signature_b64: str,
    sender_username: str
) -> str:
    """
    Decrypts an ECC-encrypted message using ECDH-derived AES key and verifies Ed25519 signature.
    Fetches sender's signing_public_key from MySQL (users table).
    """

    # 1) Decrypt recipient's ECDH private key
    try:
        with open(priv_key_path, "rb") as f:
            encrypted_key = f.read()
        recipient_priv_pem = decrypt_private_key(encrypted_key, password.encode())
        recipient_priv_key = ECC.import_key(recipient_priv_pem)
    except Exception as e:
        raise RuntimeError(f"Failed to decrypt your private key: {e}")

    # 2) Load sender's ECDH public key (PEM file path)
    try:
        with open(sender_pub_key_path, "rt") as f:
            sender_exchange_pub = ECC.import_key(f.read())
    except Exception as e:
        raise RuntimeError(f"Failed to load sender's exchange public key: {e}")

    # 3) Decode bundle
    nonce = base64.b64decode(nonce_b64)
    tag = base64.b64decode(tag_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    signature = base64.b64decode(signature_b64)

    # 4) Fetch sender's Ed25519 signing public key from MySQL
    try:
        conn = get_conn()
        c = conn.cursor()
        c.execute(q("SELECT signing_public_key FROM users WHERE username = ?"), (sender_username,))
        row = c.fetchone()
        conn.close()
        if not row or row[0] is None:
            raise RuntimeError("Sender's signing public key missing in DB.")
        signing_pub_pem = row[0]
        if isinstance(signing_pub_pem, memoryview):
            signing_pub_pem = signing_pub_pem.tobytes()
    except Exception as e:
        raise RuntimeError(f"Failed to fetch signing public key: {e}")

    # 5) Verify signature over (nonce||tag||ciphertext)
    to_verify = nonce + tag + ciphertext
    try:
        if not verify_blob(signing_pub_pem, to_verify, signature):
            raise RuntimeError("Signature invalid.")
    except Exception as e:
        raise RuntimeError(f"Error during signature verification: {e}")

    # 6) Derive shared AES key via ECDH and decrypt
    try:
        shared_point = sender_exchange_pub.pointQ * recipient_priv_key.d
        shared_secret = int(shared_point.x).to_bytes(32, 'big')
        aes_key = SHA256.new(shared_secret).digest()

        cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode()
    except Exception as e:
        raise RuntimeError(f"Decryption/authentication failed after signature verification: {e}")
