# encryption_utils.py
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import os

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
    shared_secret = own_private_key.exchange(peer_public_key)
    return SHA256.new(shared_secret).digest()[:32]  # 256-bit AES key

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
