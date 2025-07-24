import base64
from encryption_utils import load_key_from_file, decrypt_ecc_message

def main():
    import os
    # Prompt for usernames
    recipient_username = input("Recipient username: ")
    sender_username = input("Sender username: ")

    # Use paths relative to this script's location
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    priv_key_path = os.path.join(BASE_DIR, "keys", f"{recipient_username}_private.enc")
    pub_key_path = os.path.join(BASE_DIR, "keys", f"{sender_username}_public.pem")

    # Load recipient's private key (encrypted PEM)
    password = input(f"Password for {recipient_username}: ")
    from encryption_utils import decrypt_private_key
    encrypted_priv = load_key_from_file(priv_key_path)
    recipient_priv_pem = decrypt_private_key(encrypted_priv, password.encode()).decode()

    # Load sender's public key
    sender_pub_pem = load_key_from_file(pub_key_path).decode()

    # Prompt for message parts
    nonce_b64 = input("Nonce (base64): ")
    tag_b64 = input("Tag (base64): ")
    ciphertext_b64 = input("Ciphertext (base64): ")

    # Decrypt
    decrypted = decrypt_ecc_message(recipient_priv_pem, sender_pub_pem, nonce_b64, tag_b64, ciphertext_b64)
    print("Decrypted message:", decrypted)

if __name__ == "__main__":
    main()