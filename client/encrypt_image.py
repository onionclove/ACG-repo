#(Jingkai, Craig)
import os
from encryption_utils import import_key, decrypt_private_key, load_key_from_file, sign_blob
from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

def encrypt_and_sign_image(priv_key_path, password, recipient_pub_key_path, image_path, output_path):
    try:
        encrypted_key = load_key_from_file(priv_key_path)
        decrypted_key = decrypt_private_key(encrypted_key, password.encode())
        sender_priv_key = ECC.import_key(decrypted_key)
    except Exception as e:
        raise RuntimeError(f"Failed to decrypt sender's private key: {e}")

    try:
        with open(recipient_pub_key_path, 'rt') as f:
            recipient_pub_key = ECC.import_key(f.read())
    except Exception as e:
        raise RuntimeError(f"Failed to load recipient's public key: {e}")

    try:
        shared_point = recipient_pub_key.pointQ * sender_priv_key.d
        shared_secret = int(shared_point.x).to_bytes(32, 'big')
        aes_key = SHA256.new(shared_secret).digest()
    except Exception as e:
        raise RuntimeError(f"Failed to derive shared AES key: {e}")

    if not os.path.exists(image_path):
        raise FileNotFoundError(f"Image file not found: {image_path}")

    try:
        with open(image_path, 'rb') as f:
            image_data = f.read()

        cipher = AES.new(aes_key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(image_data)
        nonce = cipher.nonce

        to_sign = nonce + tag + ciphertext
        username = os.path.basename(priv_key_path).split('_')[0]
        signing_key_path = f"./keys/{username}_signing_private.enc"

        signing_priv_enc = load_key_from_file(signing_key_path)
        signing_priv_pem = decrypt_private_key(signing_priv_enc, password.encode())
        signature = sign_blob(signing_priv_pem, to_sign)

        with open(output_path, 'wb') as f:
            f.write(nonce + tag + ciphertext + signature)

        return True
    except Exception as e:
        raise RuntimeError(f"Failed to encrypt and sign image: {e}")
