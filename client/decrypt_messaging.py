import os
from getpass import getpass
from encryption_utils import (
    import_key,
    decrypt_private_key,
    load_key_from_file,
    verify_blob,
)
from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import sqlite3

DB_PATH = '../server/db/user_db.sqlite'  # adjust if needed

def decrypt_image_from_logged_in():
    print("=== ECC Image Decryption with Signature Verification ===")

    # === Step 1: Get paths and password ===
    priv_key_path = input("Enter path to your encrypted private key (.enc): ").strip()
    password = getpass("Enter your password: ").strip()
    sender_pub_key_path = input("Enter path to sender's exchange public key (.pem): ").strip()
    encrypted_image_path = input("Enter path to encrypted+signed image file: ").strip()
    output_path = input("Enter output filename (e.g., decrypted.jpg): ").strip()
    sender_username = input("Enter sender's username (for signature key lookup): ").strip()

    # === Step 2: Decrypt your exchange private key ===
    try:
        encrypted_key = load_key_from_file(priv_key_path)
        decrypted_key = decrypt_private_key(encrypted_key, password.encode())
        recipient_priv_key = ECC.import_key(decrypted_key)
    except Exception as e:
        print("❌ Failed to decrypt your exchange private key:", e)
        return

    # === Step 3: Load sender's exchange public key ===
    try:
        with open(sender_pub_key_path, 'rt') as f:
            sender_exchange_pub = ECC.import_key(f.read())
    except Exception as e:
        print("❌ Failed to load sender's exchange public key:", e)
        return

    # === Step 4: Read encrypted+signed file ===
    if not os.path.exists(encrypted_image_path):
        print("❌ Encrypted image not found:", encrypted_image_path)
        return

    try:
        data = open(encrypted_image_path, 'rb').read()
        if len(data) < 16 + 16 + 64:
            print("❌ File too short to contain nonce, tag, ciphertext, and signature.")
            return

        nonce = data[:16]
        tag = data[16:32]
        signature = data[-64:]
        ciphertext = data[32:-64]
    except Exception as e:
        print("❌ Failed to parse encrypted file:", e)
        return

    # === Step 5: Load sender's signing public key from DB ===
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT signing_public_key FROM users WHERE username = ?", (sender_username,))
        row = c.fetchone()
        conn.close()
        if not row or row[0] is None:
            print("❌ Sender's signing public key missing in DB.")
            return
        signing_pub_pem = row[0]
        if isinstance(signing_pub_pem, memoryview):
            signing_pub_pem = signing_pub_pem.tobytes()
    except Exception as e:
        print("❌ Failed to fetch signing public key from DB:", e)
        return

    # === Step 6: Verify signature ===
    to_verify = nonce + tag + ciphertext
    try:
        if not verify_blob(signing_pub_pem, to_verify, signature):
            print("❌ Signature invalid. Aborting decryption.")
            return
    except Exception as e:
        print("❌ Error during signature verification:", e)
        return

    print("[+] Signature verified.")

    # === Step 7: Derive shared AES key ===
    try:
        shared_point = sender_exchange_pub.pointQ * recipient_priv_key.d
        shared_secret = int(shared_point.x).to_bytes(32, 'big')
        aes_key = SHA256.new(shared_secret).digest()
    except Exception as e:
        print("❌ Failed to derive shared key:", e)
        return

    # === Step 8: Decrypt image ===
    try:
        cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        with open(output_path, 'wb') as f:
            f.write(plaintext)
        print(f"[+] Decrypted image saved to: {output_path}")
    except Exception as e:
        print("❌ Decryption/authentication failed after signature verification:", e)


if __name__ == "__main__":
    decrypt_image_from_logged_in()
