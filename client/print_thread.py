# xukai
import os, time, tempfile
from mysql_wb import get_conn, q, ensure_tables
from decrypt_messaging import decrypt_and_verify_message

def load_thread(me, pw, peer, only_today=True):
    ensure_tables()
    conn = get_conn()
    try:
        c = conn.cursor(dictionary=True)

        where_today = "AND m.ts >= UNIX_TIMESTAMP(CURDATE())" if only_today else ""
        # IMPORTANT: select BOTH keys; we'll use public_key for ECDH
        c.execute(q(f"""
            SELECT
                m.sender, m.recipient, m.ts,
                m.nonce_base64, m.tag_base64, m.ct_base64, m.signature_base64,
                u.public_key, u.signing_public_key
            FROM messages m
            JOIN users u ON u.username = m.sender
            WHERE ((m.sender=? AND m.recipient=?) OR (m.sender=? AND m.recipient=?))
              {where_today}
            ORDER BY m.ts ASC
        """), (me, peer, peer, me))
        rows = c.fetchall()
    finally:
        conn.close()

    out = []
    for r in rows:
        sender = r["sender"]

        # --- write sender's ECDH public key (NOT signing key) to a temp PEM file ---
        pub_bytes = r["public_key"]
        if isinstance(pub_bytes, memoryview):
            pub_bytes = pub_bytes.tobytes()
        if isinstance(pub_bytes, str):
            pub_bytes = pub_bytes.encode()

        with tempfile.NamedTemporaryFile(delete=False, suffix="_pub.pem") as tf:
            tf.write(pub_bytes)
            sender_pub_path = tf.name

        # --- decrypt + verify (function will verify signature using sender_username) ---
        try:
            plaintext = decrypt_and_verify_message(
                priv_key_path=os.path.join("keys", f"{me}_private.enc"),
                password=pw,
                sender_pub_key_path=sender_pub_path,   # ECDH key for shared secret
                nonce_b64=r["nonce_base64"],
                tag_b64=r["tag_base64"],
                ciphertext_b64=r["ct_base64"],
                signature_b64=r["signature_base64"],
                sender_username=sender
            )
            out.append((int(r["ts"]), sender, plaintext))
        except Exception as e:
            out.append((int(r["ts"]), sender, f"[DECRYPT FAIL: {e}]"))
        finally:
            try:
                os.unlink(sender_pub_path)
            except Exception:
                pass

    return out

if __name__ == "__main__":
    me   = input("My username: ").strip()
    pw   = input("My password: ").strip()
    peer = input("Peer username: ").strip()

    msgs = load_thread(me, pw, peer, only_today=True)
    if not msgs:
        print("No messages found for this conversation.")
    else:
        print(f"\n=== Chat {me} ↔ {peer} ===")
        for ts, sender, body in msgs:
            tstr = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
            print(f"{tstr}  {sender}: {body}")