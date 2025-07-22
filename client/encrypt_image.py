import os
from getpass import getpass
from encryption_utils import import_key, decrypt_private_key, load_key_from_file
from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

def send_image_from_logged_in():
    print("\n=== ECC Image Encryption ===")

    # === Step 1: Get paths and password ===
    priv_key_path = input("Enter path to your encrypted private key (.enc): ").strip()
    password = getpass("Enter your password: ").strip()
    recipient_pub_key_path = input("Enter path to recipient's public key (.pem): ").strip()
    image_path = input("Enter path to the image file: ").strip()
    output_path = input("Enter output filename (e.g., encrypted.enc): ").strip()

    # === Step 2: Decrypt private key ===
    try:
        encrypted_key = load_key_from_file(priv_key_path)
        decrypted_key = decrypt_private_key(encrypted_key, password.encode())
        sender_priv_key = ECC.import_key(decrypted_key)
    except Exception as e:
        print("❌ Failed to decrypt your private key:", e)
        return

    # === Step 3: Load recipient public key ===
    try:
        with open(recipient_pub_key_path, 'rt') as f:
            recipient_pub_key = ECC.import_key(f.read())
    except Exception as e:
        print("❌ Failed to load recipient's public key:", e)
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

        with open(output_path, 'wb') as f:
            f.write(cipher.nonce + tag + ciphertext)

        print(f"[+] Encrypted image saved to: {output_path}")
    except Exception as e:
        print("❌ Failed to encrypt image:", e)

if __name__ == "__main__":
    send_image_from_logged_in()
