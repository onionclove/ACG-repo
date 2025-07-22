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

