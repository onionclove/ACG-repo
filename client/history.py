#xukai
from mysql_wb import get_conn, q, ensure_tables
from decrypt_messaging import decrypt_and_verify_message

def load_thread(my_username: str, my_password: str, peer_username: str):
    """
    Pulls all ciphertext between me and peer (both directions), ordered by time,
    and returns a list of dicts: {from, to, ts, body}
    """
    ensure_tables()
    conn = get_conn()
    try:
        c = conn.cursor(dictionary=True)
        c.execute(q("""
            SELECT sender, recipient, ts, nonce_base64, tag_base64, ct_base64, signature_base64
            FROM messages
            WHERE (sender = ? AND recipient = ?) OR (sender = ? AND recipient = ?)
            ORDER BY ts ASC
        """), (my_username, peer_username, peer_username, my_username))
        rows = c.fetchall()
    finally:
        conn.close()

    out = []
    for r in rows:
        sender = r["sender"]
        sender_pub_path = f"./keys/{sender}_public.pem"

        try:
            plaintext = decrypt_and_verify_message(
                priv_key_path=f"./keys/{my_username}_private.enc",
                password=my_password,
                sender_pub_key_path=sender_pub_path,
                nonce_b64=r["nonce_base64"],
                tag_b64=r["tag_base64"],
                ciphertext_b64=r["ct_base64"],
                signature_b64=r["signature_base64"],
                sender_username=sender
            )
            out.append({
                "from": r["sender"],
                "to":   r["recipient"],
                "ts":   int(r["ts"]),
                "body": plaintext
            })
        except Exception as e:
            out.append({
                "from": r["sender"],
                "to":   r["recipient"],
                "ts":   int(r["ts"]),
                "body": f"[DECRYPTION FAILED: {e}]"
            })
    return out
