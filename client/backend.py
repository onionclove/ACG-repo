import os, json, socket, base64, hashlib, threading, sqlite3
from encryption_utils import (
    generate_dh_keypair, export_key, encrypt_private_key, save_key_to_file,
    decrypt_private_key, load_key_from_file, sign_blob
)
from encrypt_image import encrypt_and_sign_image as encrypt_and_sign_file
from decrypt_image import decrypt_and_verify_image as decrypt_and_verify_file
from decrypt_messaging import decrypt_and_verify_message
from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

DB_PATH = '../server/db/user_db.sqlite'
KEY_DIR = './keys/'

def ensure_tables():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        salt BLOB,
        hash BLOB,
        public_key BLOB,
        signing_public_key BLOB
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS online_users (
        username TEXT PRIMARY KEY,
        ip_address TEXT NOT NULL,
        port INTEGER NOT NULL,
        updated_on TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    conn.commit()
    conn.close()

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
    ensure_tables()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ?", (username,))
    if c.fetchone():
        raise ValueError("Username already exists.")
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
    save_key_to_file(KEY_DIR + f'{username}_public.pem', pub_key_pem)
    save_key_to_file(KEY_DIR + f'{username}_private.enc', encrypted_priv_key)
    save_key_to_file(KEY_DIR + f'{username}_signing_private.enc', encrypted_sign_priv)
    salt = os.urandom(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    c.execute("INSERT INTO users (username, salt, hash, public_key, signing_public_key) VALUES (?, ?, ?, ?, ?)",
              (username, salt, pwd_hash, pub_key_pem, sign_pub_pem))
    conn.commit()
    conn.close()

def login_user(username, password, ip, port):
    ensure_tables()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT salt, hash FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    if not row:
        raise ValueError("User not found.")
    salt, stored_hash = row
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    if pwd_hash != stored_hash:
        raise ValueError("Incorrect password.")
    c.execute("INSERT OR REPLACE INTO online_users (username, ip_address, port) VALUES (?, ?, ?)", (username, ip, port))
    conn.commit()
    conn.close()

def send_text_message(sender, password, recipient, message):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT public_key FROM users WHERE username = ?", (recipient,))
    pub_row = c.fetchone()
    c.execute("SELECT ip_address, port FROM online_users WHERE username = ?", (recipient,))
    ip_row = c.fetchone()
    conn.close()
    if not pub_row or not ip_row:
        raise ValueError("Recipient not found or offline.")
    recipient_pub_pem = pub_row[0]
    if isinstance(recipient_pub_pem, memoryview):
        recipient_pub_pem = recipient_pub_pem.tobytes()
    recipient_pub_key = ECC.import_key(recipient_pub_pem)
    recipient_ip, recipient_port = ip_row
    priv_key_pem = decrypt_private_key(load_key_from_file(f"{KEY_DIR}{sender}_private.enc"), password.encode())
    sender_priv_key = ECC.import_key(priv_key_pem)
    shared_secret = sender_priv_key.d * recipient_pub_key.pointQ
    aes_key = SHA256.new(int(shared_secret.x).to_bytes(32, 'big')).digest()
    cipher = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    nonce = cipher.nonce
    signing_priv_pem = decrypt_private_key(load_key_from_file(f"{KEY_DIR}{sender}_signing_private.enc"), password.encode())
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
    output_path = "temp.enc"
    encrypt_and_sign_file(
        priv_key_path=f"{KEY_DIR}{sender}_private.enc",
        password=password,
        recipient_pub_key_path=f"{KEY_DIR}{recipient}_public.pem",
        image_path=file_path,
        output_path=output_path
    )
    with open(output_path, "rb") as f:
        encrypted_data = base64.b64encode(f.read()).decode()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT ip_address, port FROM online_users WHERE username = ?", (recipient,))
    row = c.fetchone()
    conn.close()
    if not row:
        raise ValueError("Recipient not online.")
    recipient_ip, recipient_port = row
    bundle = {
        "type": "file",
        "file_data": encrypted_data,
        "filename": os.path.basename(file_path),
        "sender": sender
    }
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((recipient_ip, int(recipient_port)))
        s.sendall(json.dumps(bundle).encode())

def start_receiver(username, password, ip, port, on_message, on_file):
    def run():
        login_user(username, password, ip, port)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((ip, port))
            s.listen()
            while True:
                conn, _ = s.accept()
                with conn:
                    data = conn.recv(8192)
                    bundle = json.loads(data.decode())
                    if bundle['type'] == 'text':
                        msg = decrypt_and_verify_message(
                            priv_key_path=f"{KEY_DIR}{username}_private.enc",
                            password=password,
                            sender_pub_key_path=f"{KEY_DIR}{bundle['sender']}_public.pem",
                            nonce_b64=bundle["nonce"],
                            tag_b64=bundle["tag"],
                            ciphertext_b64=bundle["ciphertext"],
                            signature_b64=bundle["signature"],
                            sender_username=bundle['sender']
                        )
                        on_message(bundle['sender'], msg)
                    elif bundle['type'] == 'file':
                        temp_path = f"temp_{bundle['filename']}"
                        with open(temp_path, "wb") as f:
                            f.write(base64.b64decode(bundle["file_data"]))
                        output_path = "received_" + bundle['filename']
                        decrypt_and_verify_file(
                            priv_key_path=f"{KEY_DIR}{username}_private.enc",
                            password=password,
                            sender_pub_key_path=f"{KEY_DIR}{bundle['sender']}_public.pem",
                            encrypted_image_path=temp_path,
                            output_path=output_path,
                            sender_username=bundle['sender']
                        )
                        on_file(bundle['sender'], output_path)
    threading.Thread(target=run, daemon=True).start()
