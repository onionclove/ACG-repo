# decrypt_image.py  (Jingkai, Craig)
import os
import base64
from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

from encryption_utils import decrypt_private_key, verify_blob
from mysql_wb import get_conn, q

def decrypt_and_verify_image(
    priv_key_path: str,
    password: str,
    sender_pub_key_path: str,
    encrypted_image_path: str,
    output_path: str,
    sender_username: str
) -> bool:
    """
    Decrypts an ECC-encrypted & signed file (nonce||tag||ciphertext||signature).
    Verifies Ed25519 signature fetched from MySQL (users table). Outputs binary file.
    """

    # 1) Decrypt recipient private (ECDH)
    try:
        with open(priv_key_path, "rb") as f:
            encrypted_key = f.read()
        recipient_priv_pem = decrypt_private_key(encrypted_key, password.encode())
        recipient_priv_key = ECC.import_key(recipient_priv_pem)
    except Exception as e:
        raise RuntimeError(f"Failed to decrypt your exchange private key: {e}")

    # 2) Load sender public (ECDH)
    try:
        with open(sender_pub_key_path, "rt") as f:
            sender_exchange_pub = ECC.import_key(f.read())
    except Exception as e:
        raise RuntimeError(f"Failed to load sender's exchange public key: {e}")

    # 3) Read encrypted payload
    if not os.path.exists(encrypted_image_path):
        raise RuntimeError(f"Encrypted file not found: {encrypted_image_path}")
    data = open(encrypted_image_path, "rb").read()
    if len(data) < 16 + 16 + 64:
        raise RuntimeError("File too short to contain nonce, tag, ciphertext, signature.")
    nonce = data[:16]
    tag = data[16:32]
    signature = data[-64:]
    ciphertext = data[32:-64]

    # 4) Fetch sender's signing public key from MySQL
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

    # 5) Verify signature
    to_verify = nonce + tag + ciphertext
    if not verify_blob(signing_pub_pem, to_verify, signature):
        raise RuntimeError("Signature invalid.")

    # 6) ECDH -> decrypt
    try:
        shared_point = sender_exchange_pub.pointQ * recipient_priv_key.d
        shared_secret = int(shared_point.x).to_bytes(32, 'big')
        aes_key = SHA256.new(shared_secret).digest()

        cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        with open(output_path, "wb") as f:
            f.write(plaintext)
        return True
    except Exception as e:
        raise RuntimeError(f"Decryption/authentication failed after signature verification: {e}")
