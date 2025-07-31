# encryption_utils.py
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import os
import base64
from Crypto.Signature import eddsa

# DH Key Functions

def generate_dh_keypair():
    private_key = ECC.generate(curve='X25519')
    public_key = private_key.public_key()
    return private_key, public_key

def export_key(key):
    return key.export_key(format='PEM')

def import_key(pem_data):
    return ECC.import_key(pem_data)

def derive_shared_aes_key(own_private_key, peer_public_key):
    # Manual ECDH for X25519 using PyCryptodome
    shared_secret_point = own_private_key.d * peer_public_key.pointQ
    shared_secret_bytes = int(shared_secret_point.x).to_bytes(32, byteorder='big')
    return SHA256.new(shared_secret_bytes).digest()  # 256-bit AES key

# AES Encryption for Messages 

def encrypt_message(plaintext, aes_key):
    cipher = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return cipher.nonce + tag + ciphertext

def decrypt_message(enc_data, aes_key):
    nonce = enc_data[:16]
    tag = enc_data[16:32]
    ciphertext = enc_data[32:]
    cipher = AES.new(aes_key, AES.MODE_EAX, nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

# private key encryption

def encrypt_private_key(private_key_pem, password):
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32, count=100000)
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(private_key_pem)
    return salt + cipher.nonce + tag + ciphertext

def decrypt_private_key(enc_data, password):
    salt = enc_data[:16]
    nonce = enc_data[16:32]
    tag = enc_data[32:48]
    ciphertext = enc_data[48:]
    key = PBKDF2(password, salt, dkLen=32, count=100000)
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


def save_key_to_file(path, key_data):
    with open(path, 'wb') as f:
        f.write(key_data)

def load_key_from_file(path):
    with open(path, 'rb') as f:
        return f.read()

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
    from encryption_utils import import_key, derive_shared_aes_key, decrypt_message
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



def sign_blob(signing_private_pem: bytes, data: bytes) -> bytes:
    key = ECC.import_key(signing_private_pem)
    signer = eddsa.new(key, mode='rfc8032')
    return signer.sign(data)  # 64-byte signature

def verify_blob(signing_public_pem: bytes, data: bytes, signature: bytes) -> bool:
    key = ECC.import_key(signing_public_pem)
    verifier = eddsa.new(key, mode='rfc8032')
    try:
        verifier.verify(data, signature)
        return True
    except ValueError:
        return False