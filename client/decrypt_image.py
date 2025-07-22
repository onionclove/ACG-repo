import os
from getpass import getpass
from encryption_utils import import_key, decrypt_private_key, load_key_from_file
from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

def decrypt_image_from_logged_in():
    print("\n=== ECC Image Decryption ===")

    # === Step 1: Get paths and password ===
    priv_key_path = input("Enter path to your encrypted private key (.enc): ").strip()
    password = getpass("Enter your password: ").strip()
    sender_pub_key_path = input("Enter path to sender's public key (.pem): ").strip()
    encrypted_image_path = input("Enter path to encrypted image file: ").strip()
    output_path = input("Enter output filename (e.g., decrypted.jpg): ").strip()

    # === Step 2: Decrypt your private key ===
    try:
        encrypted_key = load_key_from_file(priv_key_path)
        decrypted_key = decrypt_private_key(encrypted_key, password.encode())
        recipient_priv_key = ECC.import_key(decrypted_key)
    except Exception as e:
        print("❌ Failed to decrypt your private key:", e)
        return

    # === Step 3: Load sender public key ===
    try:
        with open(sender_pub_key_path, 'rt') as f:
            sender_pub_key = ECC.import_key(f.read())
    except Exception as e:
        print("❌ Failed to load sender's public key:", e)
        return

    # === Step 4: Derive shared AES key ===
    try:
        shared_point = sender_pub_key.pointQ * recipient_priv_key.d
        shared_secret = int(shared_point.x).to_bytes(32, 'big')
        aes_key = SHA256.new(shared_secret).digest()
    except Exception as e:
        print("❌ Failed to derive shared key:", e)
        return

    # === Step 5: Load and decrypt image ===
    if not os.path.exists(encrypted_image_path):
        print("❌ Encrypted image not found:", encrypted_image_path)
        return

    try:
        with open(encrypted_image_path, 'rb') as f:
            data = f.read()

        nonce = data[:16]
        tag = data[16:32]
        ciphertext = data[32:]

        cipher = AES.new(aes_key, AES.MODE_EAX, nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)

        with open(output_path, 'wb') as f:
            f.write(plaintext)

        print(f"[+] Decrypted image saved to: {output_path}")
    except Exception as e:
        print("❌ Failed to decrypt image:", e)

if __name__ == "__main__":
    decrypt_image_from_logged_in()
