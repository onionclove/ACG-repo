# decrypt_messaging.py (supports PFS and legacy; fixed HKDF info)
import base64
from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF

from encryption_utils import decrypt_private_key, verify_blob
from mysql_wb import get_conn, q

def decrypt_and_verify_message(
    priv_key_path: str,
    password: str,
    sender_pub_key_path: str,
    nonce_b64: str,
    tag_b64: str,
    ciphertext_b64: str,
    signature_b64: str,
    sender_username: str,
    eph_pub_b64: str = None,          # optional for PFS
    recipient_username: str = None    # required for PFS HKDF info
) -> str:
    """
    Decrypts + verifies incoming message.
    If eph_pub_b64 is provided, use PFS path; otherwise fallback to static ECDH.
    """

    # 0) Load recipient static private (ECDH)
    with open(priv_key_path, "rb") as f:
        enc = f.read()
    recip_priv_pem = decrypt_private_key(enc, password.encode())
    recip_priv = ECC.import_key(recip_priv_pem)

    # 1) Load sender's exchange PUBLIC from file (legacy/non-PFS)
    with open(sender_pub_key_path, "rt") as f:
        sender_exchange_pub = ECC.import_key(f.read())

    # 2) Decode bundle parts
    nonce = base64.b64decode(nonce_b64)
    tag = base64.b64decode(tag_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    signature = base64.b64decode(signature_b64)

    # 3) Fetch sender's Ed25519 signing public key from DB
    conn = get_conn()
    c = conn.cursor()
    c.execute(q("SELECT signing_public_key FROM users WHERE username = ?"), (sender_username,))
    row = c.fetchone()
    conn.close()
    if not row or row[0] is None:
        raise RuntimeError("Sender's signing public key missing in DB.")
    sign_pub_pem = row[0]
    if isinstance(sign_pub_pem, memoryview):
        sign_pub_pem = sign_pub_pem.tobytes()

    # 4) Two modes: PFS or legacy
    if eph_pub_b64:
        # ---- PFS path ----
        if not recipient_username:
            raise RuntimeError("recipient_username is required for PFS HKDF context.")

        eph_pub_pem = base64.b64decode(eph_pub_b64)
        eph_pub = ECC.import_key(eph_pub_pem)

        # Verify signature over (eph_pub_pem || nonce || tag || ciphertext)
        to_verify = eph_pub_pem + nonce + tag + ciphertext
        if not verify_blob(sign_pub_pem, to_verify, signature):
            raise RuntimeError("Signature invalid (PFS).")

        # ECDH(recipient_static_priv × sender_ephemeral_pub)
        shared_point = eph_pub.pointQ * recip_priv.d
        shared_secret = int(shared_point.x).to_bytes(32, "big")

        # HKDF with SAME context as sender
        info = f"PFS|{sender_username}|{recipient_username}".encode()
        aes_key = HKDF(master=shared_secret, key_len=32, salt=None, hashmod=SHA256, context=info)

    else:
        # ---- Legacy static ECDH path ----
        # Verify signature over (nonce || tag || ciphertext)
        to_verify = nonce + tag + ciphertext
        if not verify_blob(sign_pub_pem, to_verify, signature):
            raise RuntimeError("Signature invalid (legacy).")

        shared_point = sender_exchange_pub.pointQ * recip_priv.d
        shared_secret = int(shared_point.x).to_bytes(32, "big")
        aes_key = SHA256.new(shared_secret).digest()

    # 5) Decrypt
    cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode()
