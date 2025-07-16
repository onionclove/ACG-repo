#This one includes the password hashing, RSA key gen and key saving/loading
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import hashlib
import os

def generate_rsa_keypair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def save_key_to_file(path, key_data):
    with open(path, 'wb') as f:
        f.write(key_data)

def load_key_from_file(path):
    with open(path, 'rb') as f:
        return f.read()

def encrypt_private_key(private_key, password):
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32, count=100000)
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(private_key)
    return salt + cipher.nonce + tag + ciphertext

def decrypt_private_key(enc_data, password):
    salt = enc_data[:16]
    nonce = enc_data[16:32]
    tag = enc_data[32:48]
    ciphertext = enc_data[48:]
    key = PBKDF2(password, salt, dkLen=32, count=100000)
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)
