import os
from getpass import getpass
from encryption_utils import import_key, decrypt_private_key, load_key_from_file, sign_blob
from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

def send_image_from_logged_in():
    print("\n=== ECC Image Encryption with Signature ===")

    # === Step 1: Get paths and password ===
    priv_key_path = input("Enter path to your encrypted private key (.enc): ").strip()
    password = getpass("Enter your password: ").strip()
    recipient_pub_key_path = input("Enter path to recipient's public key (.pem): ").strip()
    image_path = input("Enter path to the image file: ").strip()
    output_path = input("Enter output filename (e.g., encrypted_signed.enc): ").strip()

    # === Step 2: Decrypt private key (exchange key) ===
    try:
        encrypted_key = load_key_from_file(priv_key_path)
        decrypted_key = decrypt_private_key(encrypted_key, password.encode())
        sender_priv_key = ECC.import_key(decrypted_key)
    except Exception as e:
        print("❌ Failed to decrypt your exchange private key:", e)
        return

    # === Step 3: Load recipient public key (exchange) ===
    try:
        with open(recipient_pub_key_path, 'rt') as f:
            recipient_pub_key = ECC.import_key(f.read())
    except Exception as e:
        print("❌ Failed to load recipient's exchange public key:", e)
        return

    # === Step 4: Derive shared AES key ===
    try:
        shared_point = recipient_pub_key.pointQ * sender_priv_key.d
        shared_secret = int(shared_point.x).to_bytes(32, 'big')
        aes_key = SHA256.new(shared_secret).digest()
    except Exception as e:
        print("❌ Failed to derive shared key:", e)
        return

    # === Step 5: Encrypt the image ===
    if not os.path.exists(image_path):
        print("❌ Image not found:", image_path)
        return

    try:
        with open(image_path, 'rb') as f:
            image_data = f.read()

        cipher = AES.new(aes_key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(image_data)
        nonce = cipher.nonce

        # === NEW: Sign the encrypted bundle ===
        to_sign = nonce + tag + ciphertext
        signing_key_path = f"./keys/{os.path.basename(priv_key_path).split('_')[0]}_signing_private.enc"
        try:
            signing_priv_enc = load_key_from_file(signing_key_path)
            signing_priv_pem = decrypt_private_key(signing_priv_enc, password.encode())
            signature = sign_blob(signing_priv_pem, to_sign)
        except Exception as e:
            print("❌ Failed to load/decrypt/sign with signing private key:", e)
            return

        # === Write output: nonce || tag || ciphertext || signature ===
        with open(output_path, 'wb') as f:
            f.write(nonce + tag + ciphertext + signature)

        print(f"[+] Encrypted and signed image saved to: {output_path}")
    except Exception as e:
        print("❌ Failed to encrypt/sign image:", e)


if __name__ == "__main__":
    send_image_from_logged_in()
