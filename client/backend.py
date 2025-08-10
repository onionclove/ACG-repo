# Jingkai, xukai, jotish
import os
import json
import time
import socket
import base64
import threading
import hashlib
import time


from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from datetime import datetime, timedelta

from encryption_utils import (
    generate_dh_keypair, export_key, encrypt_private_key, save_key_to_file,
    decrypt_private_key, load_key_from_file, sign_blob
)
from encrypt_image import encrypt_and_sign_image as encrypt_and_sign_file
from decrypt_image import decrypt_and_verify_image as decrypt_and_verify_file
from decrypt_messaging import decrypt_and_verify_message

# MySQL adapter (ensure your mysql_wb.ensure_tables creates: users, online_users,
# offline_users, pending_messages, messages)
from mysql_wb import get_conn, ensure_tables, q

KEY_DIR = './keys/'
ONLINE_TTL = 40

# ---------------------------- AUTH HELPERS ----------------------------
def password_is_strong(password: str) -> bool:
    return (
        len(password) >= 8
        and any(c.islower() for c in password)
        and any(c.isupper() for c in password)
        and any(c.isdigit() for c in password)
        and any(c in "!@#$%^&*()-_+=" for c in password)
    )


def register_user(username: str, password: str) -> None:
    if not password_is_strong(password):
        raise ValueError(
            "Password must be at least 8 characters and include uppercase, lowercase, number, and symbol."
        )

    ensure_tables()
    conn = get_conn()
    c = conn.cursor()

    # Already exists?
    c.execute(q("SELECT 1 FROM users WHERE username = ?"), (username,))
    if c.fetchone():
        conn.close()
        raise ValueError("Username already exists.")

    # Long-term keys
    # ECDH (X25519) for exchange
    priv_key, pub_key = generate_dh_keypair()
    priv_key_pem = export_key(priv_key).encode()
    pub_key_pem = export_key(pub_key).encode()
    encrypted_priv_key = encrypt_private_key(priv_key_pem, password.encode())

    # Ed25519 for signatures
    sign_priv = ECC.generate(curve='Ed25519')
    sign_pub = sign_priv.public_key()
    sign_priv_pem = sign_priv.export_key(format='PEM').encode()
    sign_pub_pem = sign_pub.export_key(format='PEM').encode()
    encrypted_sign_priv = encrypt_private_key(sign_priv_pem, password.encode())

    os.makedirs(KEY_DIR, exist_ok=True)
    save_key_to_file(os.path.join(KEY_DIR, f'{username}_public.pem'), pub_key_pem)
    save_key_to_file(os.path.join(KEY_DIR, f'{username}_private.enc'), encrypted_priv_key)
    save_key_to_file(os.path.join(KEY_DIR, f'{username}_signing_private.enc'), encrypted_sign_priv)

    # Password hash
    salt = os.urandom(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)

    c.execute(
        q("INSERT INTO users (username, salt, hash, public_key, signing_public_key) VALUES (?, ?, ?, ?, ?)"),
        (username, salt, pwd_hash, pub_key_pem, sign_pub_pem)
    )
    conn.commit()
    conn.close()


def _verify_login(username: str, password: str) -> None:
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


def _set_online(username: str, ip: str, port: int) -> None:
    conn = get_conn()
    c = conn.cursor()
    c.execute(q("""
        INSERT INTO online_users (username, ip_address, port)
        VALUES (?, ?, ?)
        ON DUPLICATE KEY UPDATE ip_address=VALUES(ip_address),
                                port=VALUES(port),
                                updated_on=CURRENT_TIMESTAMP
    """), (username, ip, int(port)))
    # If they were in offline list, remove
    c.execute(q("DELETE FROM offline_users WHERE username = ?"), (username,))
    conn.commit()
    conn.close()


def _resolve_online(username: str):
    conn = get_conn()
    c = conn.cursor()
    c.execute(q("SELECT ip_address, port FROM online_users WHERE username = ?"), (username,))
    row = c.fetchone()
    conn.close()
    return row  # (ip, port) or None


def _enqueue_message(recipient: str, sender: str, msg_type: str, payload: bytes) -> None:
    """Store a message for later delivery when recipient is offline.
    msg_type: 'text' | 'file'
    payload: raw JSON bytes
    """
    ensure_tables()
    conn = get_conn()
    c = conn.cursor()
    c.execute(q("""
        INSERT INTO pending_messages (recipient, sender, msg_type, payload)
        VALUES (?, ?, ?, ?)
    """), (recipient, sender, msg_type, payload))
    conn.commit()
    conn.close()


def _drain_pending(recipient: str, password: str, on_message, on_file) -> None:
    """Deliver queued messages to this recipient now that they are online."""
    ensure_tables()
    conn = get_conn()
    c = conn.cursor()
    c.execute(q("""
        SELECT id, sender, msg_type, payload
        FROM pending_messages
        WHERE recipient = ? AND delivered = 0
        ORDER BY id ASC
    """), (recipient,))
    rows = c.fetchall() or []
    for msg_id, sender, msg_type, payload in rows:
        try:
            bundle = json.loads(payload.decode())

            if msg_type == 'text':
                msg = decrypt_and_verify_message(
                    priv_key_path=os.path.join(KEY_DIR, f"{recipient}_private.enc"),
                    password=password,
                    sender_pub_key_path=os.path.join(KEY_DIR, f"{sender}_public.pem"),
                    nonce_b64=bundle["nonce"],
                    tag_b64=bundle["tag"],
                    ciphertext_b64=bundle["ciphertext"],
                    signature_b64=bundle["signature"],
                    sender_username=sender,
                    eph_pub_b64=bundle.get("eph_pub"),
                    recipient_username=recipient,
                )
                on_message(sender, msg)

            elif msg_type == 'file':
                temp_path = f"temp_{bundle['filename']}"
                with open(temp_path, "wb") as f:
                    f.write(base64.b64decode(bundle["file_data"]))
                output_path = "received_" + bundle['filename']
                decrypt_and_verify_file(
                    priv_key_path=os.path.join(KEY_DIR, f"{recipient}_private.enc"),
                    password=password,
                    sender_pub_key_path=os.path.join(KEY_DIR, f"{sender}_public.pem"),
                    encrypted_image_path=temp_path,
                    output_path=output_path,
                    sender_username=sender
                )
                on_file(sender, output_path)

            # Mark delivered
            c2 = conn.cursor()
            c2.execute(q("UPDATE pending_messages SET delivered = 1 WHERE id = ?"), (msg_id,))
            conn.commit()

        except Exception:
            # keep in queue; could log
            pass

    conn.close()


def _set_offline(username: str) -> None:
    """Move user to offline_users and remove any online presence."""
    conn = get_conn()
    c = conn.cursor()
    c.execute(q("DELETE FROM online_users WHERE username = ?"), (username,))
    c.execute(q("""
        INSERT INTO offline_users (username)
        VALUES (?)
        ON DUPLICATE KEY UPDATE last_offline=CURRENT_TIMESTAMP
    """), (username,))
    conn.commit()
    conn.close()


# ---------------------------- NET HELPERS ----------------------------
def _best_local_ip() -> str:
    """Pick outward-facing local IP for advertisement."""
    try:
        tmp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        tmp.connect(("8.8.8.8", 80))
        ip = tmp.getsockname()[0]
        tmp.close()
        return ip
    except Exception:
        return socket.gethostbyname(socket.gethostname())


# ---------------------------- PUBLIC API ----------------------------
def login_user(username: str, password: str, ip: str = None, port: int = None) -> None:
    """
    Verify credentials. If ip and port provided, also set presence (online_users).
    GUI can call this when it knows the port (or just rely on start_receiver).
    """
    _verify_login(username, password)
    if ip and port:
        _set_online(username, ip, int(port))


def logout_user(username: str) -> None:
    _set_offline(username)


def reset_all_presence() -> None:
    """Move all online users to offline and clear the online table."""
    ensure_tables()
    conn = get_conn()
    c = conn.cursor()
    c.execute(q("SELECT username FROM online_users"))
    rows = c.fetchall() or []
    for (uname,) in rows:
        c.execute(q("""
            INSERT INTO offline_users (username)
            VALUES (?)
            ON DUPLICATE KEY UPDATE last_offline=CURRENT_TIMESTAMP
        """), (uname,))
    c.execute(q("DELETE FROM online_users"))
    conn.commit()
    conn.close()




def is_user_online(username: str) -> bool:
    ensure_tables()
    conn = get_conn()
    try:
        c = conn.cursor()
        c.execute(q("SELECT updated_on FROM online_users WHERE username = ?"), (username,))
        row = c.fetchone()
    finally:
        conn.close()

    if not row or not row[0]:
        return False

    ts = row[0]
    # MySQL returns datetime; if string, parse ISO
    if isinstance(ts, str):
        try:
            ts = datetime.fromisoformat(ts.replace("Z",""))
        except Exception:
            return False

    return (datetime.utcnow() - ts) <= timedelta(seconds=ONLINE_TTL)


def _persist_message_history(bundle: dict, recipient: str) -> None:
    """Optional: store inbound ciphertext (for demo/audit)."""
    try:
        ensure_tables()
        conn2 = get_conn()
        c2 = conn2.cursor()

        # make stable text id
        base = (bundle["sender"] + "|" + recipient + "|" + bundle["nonce"] + bundle["tag"] + bundle["ciphertext"]).encode()
        msg_id = SHA256.new(base).hexdigest()

        c2.execute(q("""
            INSERT IGNORE INTO messages
            (msg_id, sender, recipient, ts, nonce_base64, tag_base64, ct_base64, signature_base64)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """), (
            msg_id,
            bundle["sender"],
            recipient,
            int(bundle.get("ts") or time.time()),
            bundle["nonce"],
            bundle["tag"],
            bundle["ciphertext"],
            bundle["signature"]
        ))
        conn2.commit()
    except Exception:
        pass
    finally:
        try:
            conn2.close()
        except Exception:
            pass


def send_text_message(sender: str, password: str, recipient: str, message: str) -> None:
    """Legacy static-ECDH send. Queues if recipient offline."""
    ensure_tables()

    # Recipient key
    conn = get_conn()
    c = conn.cursor()
    c.execute(q("SELECT public_key FROM users WHERE username = ?"), (recipient,))
    pub_row = c.fetchone()
    conn.close()
    if not pub_row:
        raise ValueError("Recipient not registered.")

    # Online?
    ip_port = _resolve_online(recipient)
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

    # Keep a local plaintext copy so history shows your side
    _store_sent_copy(sender, recipient, message, int(time.time()))

    # Queue if offline
    if not ip_port:
        _enqueue_message(recipient, sender, 'text', json.dumps(bundle).encode())
        return

    # Send now
    recipient_ip, recipient_port = ip_port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(5)
        s.connect((recipient_ip, int(recipient_port)))
        s.sendall(json.dumps(bundle).encode())


def send_text_message_pfs(sender: str, password: str, recipient: str, message: str) -> None:
    ensure_tables()

    # 1) recipient pubkey (needed to encrypt even if offline)
    conn = get_conn()
    c = conn.cursor()
    c.execute(q("SELECT public_key FROM users WHERE username = ?"), (recipient,))
    pub_row = c.fetchone()
    conn.close()
    if not pub_row:
        raise ValueError("Recipient not registered.")

    recipient_pub_pem = pub_row[0]
    if isinstance(recipient_pub_pem, memoryview):
        recipient_pub_pem = recipient_pub_pem.tobytes()
    recipient_pub_key = ECC.import_key(recipient_pub_pem)

    # 2) build the PFS bundle (ephemeral key, HKDF, encrypt, sign)
    eph_priv, eph_pub = generate_dh_keypair()
    eph_pub_pem = export_key(eph_pub).encode()

    shared_point = recipient_pub_key.pointQ * eph_priv.d
    shared_secret = int(shared_point.x).to_bytes(32, "big")

    info = f"PFS|{sender}|{recipient}".encode()
    aes_key = HKDF(master=shared_secret, key_len=32, salt=None, hashmod=SHA256, context=info)

    cipher = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    nonce = cipher.nonce

    signing_priv_pem = decrypt_private_key(
        load_key_from_file(os.path.join(KEY_DIR, f"{sender}_signing_private.enc")),
        password.encode()
    )
    signature = sign_blob(signing_priv_pem, eph_pub_pem + nonce + tag + ciphertext)

    bundle = {
        "type": "text",
        "pfs": True,
        "eph_pub": base64.b64encode(eph_pub_pem).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "tag": base64.b64encode(tag).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "signature": base64.b64encode(signature).decode(),
        "sender": sender
    }

    _store_sent_copy(sender, recipient, message, int(time.time()))

    # 3) try live send; if offline, queue instead of raising
    ip_port = _resolve_online(recipient)
    if not ip_port:
        _enqueue_message(recipient, sender, 'text', json.dumps(bundle).encode())
        return

    recipient_ip, recipient_port = ip_port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(5)
        s.connect((recipient_ip, int(recipient_port)))
        s.sendall(json.dumps(bundle).encode())


def send_encrypted_file(sender: str, password: str, recipient: str, file_path: str) -> None:
    """Encrypt+sign any binary file and send (or queue if offline)."""
    ensure_tables()

    # encrypt file to temp.enc (nonce||tag||ciphertext||signature)
    output_path = "temp.enc"
    encrypt_and_sign_file(
        priv_key_path=os.path.join(KEY_DIR, f"{sender}_private.enc"),
        password=password,
        recipient_pub_key_path=os.path.join(KEY_DIR, f"{recipient}_public.pem"),
        image_path=file_path,      # works for any binary
        output_path=output_path
    )
    with open(output_path, "rb") as f:
        encrypted_data = base64.b64encode(f.read()).decode()

    ip_port = _resolve_online(recipient)
    bundle = {
        "type": "file",
        "file_data": encrypted_data,
        "filename": os.path.basename(file_path),
        "sender": sender
    }

    if not ip_port:
        _enqueue_message(recipient, sender, 'file', json.dumps(bundle).encode())
        return

    recipient_ip, recipient_port = ip_port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(5)
        s.connect((recipient_ip, int(recipient_port)))
        s.sendall(json.dumps(bundle).encode())


def start_receiver(username: str, password: str, on_message, on_file) -> int:
    """
    Binds on 0.0.0.0 with an OS-chosen port; registers (ip, port) in online_users;
    returns the bound port. Runs accept loop in a daemon thread and dispatches to callbacks.
    """
    _verify_login(username, password)

    def run_server():
        ip = "0.0.0.0"
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((ip, 0))  # ephemeral port
        srv.listen()
        bound_port = srv.getsockname()[1]

        adv_ip = _best_local_ip()
        _set_online(username, adv_ip, bound_port)

        start_receiver.bound_port = bound_port
        start_receiver.server_socket = srv

        # On becoming online, drain queued messages
        # try:
        #     _drain_pending(username, password, on_message, on_file)
        # except Exception:
        #     pass

        while not start_receiver.stop_event.is_set():
            try:
                conn, _addr = srv.accept()
            except OSError:
                break
            threading.Thread(
                target=_handle_conn,
                args=(conn, username, password, on_message, on_file),
                daemon=True
            ).start()

        try:
            srv.close()
        except Exception:
            pass

    def _handle_conn(conn, my_username, my_password, cb_msg, cb_file):
        with conn:
            try:
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
                        sender_username=bundle['sender'],
                        eph_pub_b64=bundle.get("eph_pub"),      # PFS if present
                        recipient_username=my_username          # HKDF info match
                    )
                    cb_msg(bundle['sender'], msg)
                    _persist_message_history(bundle, my_username)

                elif bundle.get("type") == "file":
                    temp_path = f"temp_{bundle['filename']}"
                    with open(temp_path, "wb") as f:
                        f.write(base64.b64decode(bundle["file_data"]))
                    output_path = "received_" + bundle['filename']
                    decrypt_and_verify_file(
                        priv_key_path=os.path.join(KEY_DIR, f"{my_username}_private.enc"),
                        password=my_password,
                        sender_pub_key_path=os.path.join(KEY_DIR, f"{bundle['sender']}_public.pem"),
                        encrypted_image_path=temp_path,
                        output_path=output_path,
                        sender_username=bundle['sender']
                    )
                    cb_file(bundle['sender'], output_path)

            except Exception:
                import traceback
                print("[Receiver] Error handling inbound packet:")
                traceback.print_exc()

    start_receiver.stop_event = threading.Event()
    t = threading.Thread(target=run_server, daemon=True)
    t.start()

    while getattr(start_receiver, "bound_port", None) is None:
        pass

    return start_receiver.bound_port


def stop_receiver():
    ev = getattr(start_receiver, "stop_event", None)
    if ev:
        ev.set()
    srv = getattr(start_receiver, "server_socket", None)
    if srv:
        try:
            srv.close()
        except Exception:
            pass

def get_pending_for_pair(recipient: str, other_party: str):
    """
    Return list of (id, sender, msg_type, payload_json_bytes) for this chat.
    Only rows addressed to `recipient` and from/to `other_party`.
    """
    ensure_tables()
    conn = get_conn()
    c = conn.cursor()
    c.execute(q("""
        SELECT id, sender, msg_type, payload
        FROM pending_messages
        WHERE recipient = ?
          AND sender = ?
          AND delivered = 0
        ORDER BY id ASC
    """), (recipient, other_party))
    rows = c.fetchall() or []
    conn.close()
    return rows


def move_pending_to_messages(ids: list[int]):
    """
    Move a set of pending rows into the messages table, then delete them.
    We keep the original JSON payload and mark as was_offline=1.
    """
    if not ids:
        return
    ensure_tables()
    conn = get_conn()
    c = conn.cursor()

    # Insert into messages (adjust column names to your schema)
    # Example messages schema assumed:
    # messages(msg_id PK, sender, recipient, ts, nonce_base64, tag_base64, ct_base64,
    #          signature_base64, pfs, eph_pub_base64, is_offline)
    #
    # Since pending stores a JSON payload, we rehydrate fields here.
    # We’ll do it row-by-row to stay DB-agnostic.
    c2 = conn.cursor()
    c3 = conn.cursor()
    for pid in ids:
        c2.execute(q("SELECT recipient, sender, msg_type, payload FROM pending_messages WHERE id = ?"), (pid,))
        row = c2.fetchone()
        if not row:
            continue
        recipient, sender, msg_type, payload = row
        try:
            bundle = json.loads(payload.decode())
        except Exception:
            bundle = {}

        ts = int(bundle.get("ts") or time.time())
        nonce_b64 = bundle.get("nonce", "")
        tag_b64 = bundle.get("tag", "")
        ct_b64 = bundle.get("ciphertext", "")
        sig_b64 = bundle.get("signature", "")
        pfs = 1 if bundle.get("pfs") else 0
        eph_pub_b64 = bundle.get("eph_pub", "")

        # Deterministic msg_id (same logic as _persist_message_history)
        base = (bundle.get("sender","") + "|" + recipient + "|" + nonce_b64 + tag_b64 + ct_b64).encode()
        msg_id = SHA256.new(base).hexdigest()

        c3.execute(q("""
    INSERT IGNORE INTO messages
    (msg_id, sender, recipient, ts, nonce_base64, tag_base64, ct_base64, signature_base64)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
"""), (
    msg_id,
    sender,
    recipient,
    ts,
    nonce_b64,
    tag_b64,
    ct_b64,
    sig_b64
))

        # Finally delete the pending row
        c3.execute(q("DELETE FROM pending_messages WHERE id = ?"), (pid,))

    conn.commit()
    conn.close()


def view_pending_for_contact(current_user: str, contact: str, password: str, on_message, on_file):
    """
    Load all undelivered pending messages in this 1:1 chat.
    Decrypt/verify and dispatch to callbacks (so the user 'views' them).
    Move them into messages table and delete from pending.
    """
    rows = get_pending_for_pair(recipient=current_user, other_party=contact)
    if not rows:
        return 0

    moved_ids = []
    for pid, sender, msg_type, payload in rows:
        try:
            bundle = json.loads(payload.decode())

            if msg_type == 'text':
                msg = decrypt_and_verify_message(
                    priv_key_path=os.path.join(KEY_DIR, f"{current_user}_private.enc"),
                    password=password,
                    sender_pub_key_path=os.path.join(KEY_DIR, f"{sender}_public.pem"),
                    nonce_b64=bundle["nonce"],
                    tag_b64=bundle["tag"],
                    ciphertext_b64=bundle["ciphertext"],
                    signature_b64=bundle["signature"],
                    sender_username=sender,
                    eph_pub_b64=bundle.get("eph_pub"),
                    recipient_username=current_user,
                )
                on_message(sender, msg)

            elif msg_type == 'file':
                temp_path = f"temp_{bundle['filename']}"
                with open(temp_path, "wb") as f:
                    f.write(base64.b64decode(bundle["file_data"]))
                output_path = "received_" + bundle['filename']
                decrypt_and_verify_file(
                    priv_key_path=os.path.join(KEY_DIR, f"{current_user}_private.enc"),
                    password=password,
                    sender_pub_key_path=os.path.join(KEY_DIR, f"{sender}_public.pem"),
                    encrypted_image_path=temp_path,
                    output_path=output_path,
                    sender_username=sender
                )
                on_file(sender, output_path)

            moved_ids.append(pid)

        except Exception:
            # If decryption fails, do not move/delete; leave for later troubleshooting.
            import traceback; traceback.print_exc()

    # Only after user has 'seen' them (callbacks fired), move → messages & delete
    move_pending_to_messages(moved_ids)
    return len(moved_ids)


def list_all_users(exclude: str | None = None) -> list[str]:
    """Return all usernames (optionally exclude the current user)."""
    ensure_tables()
    conn = get_conn()
    try:
        c = conn.cursor()
        if exclude:
            c.execute(q("SELECT username FROM users WHERE username <> ? ORDER BY username"), (exclude,))
        else:
            c.execute(q("SELECT username FROM users ORDER BY username"))
        return [row[0] for row in (c.fetchall() or [])]
    finally:
        conn.close()


def get_chat_history(current_user: str, password: str, contact: str, limit: int = 500):
    """
    Return [(sender, plaintext, ts), ...] oldest-first for current_user <-> contact.
    Decrypt incoming from `messages`; merge with your local plaintext copies in `sent_messages`.
    """
    ensure_tables()
    conn = get_conn()
    try:
        c = conn.cursor()

        # 1) Load both directions from messages (ciphertexts) in chronological order
        c.execute(q("""
            SELECT sender, recipient, ts, nonce_base64, tag_base64, ct_base64, signature_base64
            FROM messages
            WHERE (sender = ? AND recipient = ?)
               OR (sender = ? AND recipient = ?)
            ORDER BY ts ASC
            LIMIT ?
        """), (current_user, contact, contact, current_user, int(limit)))
        cipher_rows = c.fetchall() or []

        incoming = []
        for sender, _recipient, ts, nonce_b64, tag_b64, ct_b64, sig_b64 in cipher_rows:
            # Only decrypt messages addressed TO current_user; messages you sent are not decryptable by you
            if _recipient != current_user:
                continue
            try:
                msg = decrypt_and_verify_message(
                    priv_key_path=os.path.join(KEY_DIR, f"{current_user}_private.enc"),
                    password=password,
                    sender_pub_key_path=os.path.join(KEY_DIR, f"{sender}_public.pem"),
                    nonce_b64=nonce_b64,
                    tag_b64=tag_b64,
                    ciphertext_b64=ct_b64,
                    signature_b64=sig_b64,
                    sender_username=sender,
                    eph_pub_b64=None,
                    recipient_username=current_user
                )
                incoming.append((sender, msg, int(ts)))
            except Exception:
                # skip corrupt/legacy rows
                continue

        # 2) Load your locally-stored plaintext copies of messages you SENT
        c.execute(q("""
            SELECT sender, recipient, ts, plaintext
            FROM sent_messages
            WHERE sender = ? AND recipient = ?
            ORDER BY ts ASC
            LIMIT ?
        """), (current_user, contact, int(limit)))
        sent_rows = c.fetchall() or []
        sent = [(s, p, int(t)) for (s, _r, t, p) in sent_rows]

    finally:
        conn.close()

    # 3) Merge and trim
    merged = incoming + sent
    merged.sort(key=lambda x: x[2])
    if len(merged) > limit:
        merged = merged[-limit:]
    return merged

def _store_sent_copy(sender: str, recipient: str, plaintext: str, ts: int | None = None) -> None:
    ensure_tables()
    conn = get_conn()
    try:
        c = conn.cursor()
        c.execute(q("""
            INSERT INTO sent_messages (sender, recipient, ts, plaintext)
            VALUES (?, ?, ?, ?)
        """), (sender, recipient, int(ts or time.time()), plaintext))
        conn.commit()
    finally:
        conn.close()