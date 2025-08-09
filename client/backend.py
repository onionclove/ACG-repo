# backend.py
import os, json, socket, base64, hashlib, threading
from datetime import datetime
from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

from encryption_utils import (
    generate_dh_keypair, export_key, encrypt_private_key, save_key_to_file,
    decrypt_private_key, load_key_from_file, sign_blob
)
from encrypt_image import encrypt_and_sign_image as encrypt_and_sign_file
from decrypt_image import decrypt_and_verify_image as decrypt_and_verify_file
from decrypt_messaging import decrypt_and_verify_message

# === MySQL adapter ===
from mysql_wb import get_conn, ensure_tables, q

KEY_DIR = './keys/'

# ---------- AUTH HELPERS ----------
def password_is_strong(password):
    return (
        len(password) >= 8 and
        any(c.islower() for c in password) and
        any(c.isupper() for c in password) and
        any(c.isdigit() for c in password) and
        any(c in "!@#$%^&*()-_+=" for c in password)
    )

def register_user(username, password):
    if not password_is_strong(password):
        raise ValueError("Password must be at least 8 characters and include uppercase, lowercase, number, and symbol.")

    ensure_tables() # Ensure tables exist in mySQL workbench
    conn = get_conn()
    c = conn.cursor()

    # Already exists?
    c.execute(q("SELECT 1 FROM users WHERE username = ?"), (username,))
    if c.fetchone():
        conn.close()
        raise ValueError("Username already exists.")

    # Keys
    priv_key, pub_key = generate_dh_keypair()
    priv_key_pem = export_key(priv_key).encode()
    pub_key_pem = export_key(pub_key).encode()
    encrypted_priv_key = encrypt_private_key(priv_key_pem, password.encode())

    sign_priv = ECC.generate(curve='Ed25519')
    sign_pub = sign_priv.public_key()
    sign_priv_pem = sign_priv.export_key(format='PEM').encode()
    sign_pub_pem = sign_pub.export_key(format='PEM').encode()
    encrypted_sign_priv = encrypt_private_key(sign_priv_pem, password.encode())

    os.makedirs(KEY_DIR, exist_ok=True)
    save_key_to_file(os.path.join(KEY_DIR, f'{username}_public.pem'), pub_key_pem)
    save_key_to_file(os.path.join(KEY_DIR, f'{username}_private.enc'), encrypted_priv_key)
    save_key_to_file(os.path.join(KEY_DIR, f'{username}_signing_private.enc'), encrypted_sign_priv)

    salt = os.urandom(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)

    c.execute(
        q("INSERT INTO users (username, salt, hash, public_key, signing_public_key) VALUES (?, ?, ?, ?, ?)"),
        (username, salt, pwd_hash, pub_key_pem, sign_pub_pem)
    )
    conn.commit()
    conn.close()

def _verify_login(username, password):
    ensure_tables()
    conn = get_conn()
    c = conn.cursor()
    c.execute(q("SELECT salt, hash FROM users WHERE username = ?"), (username,))
    row = c.fetchone()
    conn.close()
    if not row:
        raise ValueError("User not found.")
    salt, stored_hash = row
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    if pwd_hash != stored_hash:
        raise ValueError("Incorrect password.")

def _set_online(username, ip, port):
    """
    Upsert into online_users
    """
    conn = get_conn()
    c = conn.cursor()
    c.execute(q("""
        INSERT INTO online_users (username, ip_address, port)
        VALUES (?, ?, ?)
        ON DUPLICATE KEY UPDATE ip_address=VALUES(ip_address), port=VALUES(port), updated_on=CURRENT_TIMESTAMP
    """), (username, ip, int(port)))
    conn.commit()
    conn.close()

def _resolve_online(username):
    conn = get_conn()
    c = conn.cursor()
    c.execute(q("SELECT ip_address, port FROM online_users WHERE username = ?"), (username,))
    row = c.fetchone()
    conn.close()
    return row  # (ip, port) or None

# ---------- NET HELPERS ----------
def _best_local_ip():
    try:
        tmp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        tmp.connect(("8.8.8.8", 80))
        ip = tmp.getsockname()[0]
        tmp.close()
        return ip
    except Exception:
        return socket.gethostbyname(socket.gethostname())

# ---------- PUBLIC API ----------
def login_user(username, password, ip=None, port=None):
    """
    Verify credentials. If ip and port provided, also set presence (online_users).
    Useful for GUI flows that want to set presence without starting the receiver yet.
    """
    _verify_login(username, password)
    if ip and port:
        _set_online(username, ip, int(port))

def send_text_message(sender, password, recipient, message):
    ensure_tables()

    # Recipient key
    conn = get_conn()
    c = conn.cursor()
    c.execute(q("SELECT public_key FROM users WHERE username = ?"), (recipient,))
    pub_row = c.fetchone()
    conn.close()
    if not pub_row:
        raise ValueError("Recipient not registered.")

    # Recipient address
    ip_port = _resolve_online(recipient)
    if not ip_port:
        raise ValueError("Recipient is offline.")
    recipient_ip, recipient_port = ip_port

    recipient_pub_pem = pub_row[0]
    if isinstance(recipient_pub_pem, memoryview):
        recipient_pub_pem = recipient_pub_pem.tobytes()
    recipient_pub_key = ECC.import_key(recipient_pub_pem)

    # Sender private (ECDH)
    priv_key_pem = decrypt_private_key(
        load_key_from_file(os.path.join(KEY_DIR, f"{sender}_private.enc")),
        password.encode()
    )
    sender_priv_key = ECC.import_key(priv_key_pem)

    # ECDH -> AES
    shared_secret = sender_priv_key.d * recipient_pub_key.pointQ
    aes_key = SHA256.new(int(shared_secret.x).to_bytes(32, 'big')).digest()

    cipher = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    nonce = cipher.nonce

    # Signature
    signing_priv_pem = decrypt_private_key(
        load_key_from_file(os.path.join(KEY_DIR, f"{sender}_signing_private.enc")),
        password.encode()
    )
    signature = sign_blob(signing_priv_pem, nonce + tag + ciphertext)

    bundle = {
        "type": "text",
        "nonce": base64.b64encode(nonce).decode(),
        "tag": base64.b64encode(tag).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "signature": base64.b64encode(signature).decode(),
        "sender": sender
    }

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((recipient_ip, int(recipient_port)))
        s.sendall(json.dumps(bundle).encode())

def send_encrypted_file(sender, password, recipient, file_path):
    ensure_tables()

    # Encrypt & sign file to temp
    output_path = "temp.enc"
    encrypt_and_sign_file(
        priv_key_path=os.path.join(KEY_DIR, f"{sender}_private.enc"),
        password=password,
        recipient_pub_key_path=os.path.join(KEY_DIR, f"{recipient}_public.pem"),
        image_path=file_path,            # function name says image, but works for any binary
        output_path=output_path
    )
    with open(output_path, "rb") as f:
        encrypted_data = base64.b64encode(f.read()).decode()

    ip_port = _resolve_online(recipient)
    if not ip_port:
        raise ValueError("Recipient is offline.")
    recipient_ip, recipient_port = ip_port

    bundle = {
        "type": "file",
        "file_data": encrypted_data,
        "filename": os.path.basename(file_path),
        "sender": sender
    }
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((recipient_ip, int(recipient_port)))
        s.sendall(json.dumps(bundle).encode())

def start_receiver(username, password, on_message, on_file):
    """
    Binds on 0.0.0.0 with an OS-chosen port; registers (ip, port) in online_users;
    returns the bound port. Runs accept loop in a daemon thread and dispatches
    to callbacks.
    """
    _verify_login(username, password)

    def run_server():
        ip = "0.0.0.0"
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((ip, 0))  # free ephemeral port
        srv.listen()
        bound_port = srv.getsockname()[1]

        adv_ip = _best_local_ip()
        _set_online(username, adv_ip, bound_port)

        start_receiver.bound_port = bound_port

        while True:
            conn, _addr = srv.accept()
            threading.Thread(
                target=_handle_conn,
                args=(conn, username, password, on_message, on_file),
                daemon=True
            ).start()

    def _handle_conn(conn, my_username, my_password, cb_msg, cb_file):
        with conn:
            # naive read-all; for large payloads switch to length-prefixed framing
            data = b""
            while True:
                chunk = conn.recv(8192)
                if not chunk:
                    break
                data += chunk
            if not data:
                return
            bundle = json.loads(data.decode())

            if bundle.get("type") == "text":
                msg = decrypt_and_verify_message(
                    priv_key_path=os.path.join(KEY_DIR, f"{my_username}_private.enc"),
                    password=my_password,
                    sender_pub_key_path=os.path.join(KEY_DIR, f"{bundle['sender']}_public.pem"),
                    nonce_b64=bundle["nonce"],
                    tag_b64=bundle["tag"],
                    ciphertext_b64=bundle["ciphertext"],
                    signature_b64=bundle["signature"],
                    sender_username=bundle['sender']
                )
                cb_msg(bundle['sender'], msg)

            elif bundle.get("type") == "file":
                temp_path = f"temp_{bundle['filename']}"
                with open(temp_path, "wb") as f:
                    f.write(base64.b64decode(bundle["file_data"]))
                output_path = "received_" + bundle['filename']
                decrypt_and_verify_file(
                    priv_key_path=os.path.join(KEY_DIR, f"{my_username}_private.enc"),
                    password=my_password,
                    sender_pub_key_path=os.path.join(KEY_DIR, f"{bundle['sender']}_public.pem"),
                    encrypted_image_path=temp_path,   # fn name says image, decrypts any binary
                    output_path=output_path,
                    sender_username=bundle['sender']
                )
                cb_file(bundle['sender'], output_path)

    t = threading.Thread(target=run_server, daemon=True)
    t.start()
    while getattr(start_receiver, "bound_port", None) is None:
        pass
    return start_receiver.bound_port
