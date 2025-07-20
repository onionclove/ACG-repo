import base64
from encryption_utils import import_key, derive_shared_aes_key, decrypt_message

#
# Decrypt a received ECC-encrypted message
#
def decrypt_ecc_message(recipient_priv_key, sender_pub_key, nonce_b64, tag_b64, ciphertext_b64):
    """
    Decrypts a message encrypted with ECC-derived AES key.
    Args:
        recipient_priv_key: ECC private key (PEM string or ECC object)
        sender_pub_key: ECC public key (PEM string or ECC object)
        nonce_b64: base64-encoded nonce (str)
        tag_b64: base64-encoded tag (str)
        ciphertext_b64: base64-encoded ciphertext (str)
    Returns:
        Decrypted plaintext (str)
    """
    # Convert keys if needed
    if isinstance(recipient_priv_key, str):
        recipient_priv_key = import_key(recipient_priv_key)
    if isinstance(sender_pub_key, str):
        sender_pub_key = import_key(sender_pub_key)

    # Derive shared AES key
    aes_key = derive_shared_aes_key(recipient_priv_key, sender_pub_key)

    # Decode base64 inputs
    nonce = base64.b64decode(nonce_b64)
    tag = base64.b64decode(tag_b64)
    ciphertext = base64.b64decode(ciphertext_b64)

    # Concatenate for decryption util
    enc_data = nonce + tag + ciphertext

    # Decrypt
    plaintext = decrypt_message(enc_data, aes_key)
    return plaintext.decode()

# Example usage (for testing only)
if __name__ == "__main__":
    from encryption_utils import generate_dh_keypair, export_key, derive_shared_aes_key, encrypt_message
    import base64

    # Generate keys for sender and recipient
    sender_priv, sender_pub = generate_dh_keypair()
    recipient_priv, recipient_pub = generate_dh_keypair()

    # Derive shared AES key (sender's perspective)
    aes_key = derive_shared_aes_key(sender_priv, recipient_pub)

    # Encrypt a message
    plaintext = b"Hello, ECC world!"
    enc_data = encrypt_message(plaintext, aes_key)

    # Split enc_data into nonce, tag, ciphertext for testing
    nonce = enc_data[:16]
    tag = enc_data[16:32]
    ciphertext = enc_data[32:]

    # Encode for transport (as your decryption function expects base64)
    nonce_b64 = base64.b64encode(nonce).decode()
    tag_b64 = base64.b64encode(tag).decode()
    ciphertext_b64 = base64.b64encode(ciphertext).decode()

    # Use recipient's private key and sender's public key (as PEM strings)
    recipient_priv_pem = export_key(recipient_priv)
    sender_pub_pem = export_key(sender_pub)

    # Decrypt
    decrypted = decrypt_ecc_message(recipient_priv_pem, sender_pub_pem, nonce_b64, tag_b64, ciphertext_b64)
    print("Original message:", plaintext.decode())
    print("Decrypted message:", decrypted)
    print("Test passed?", decrypted == plaintext.decode())
