#!/usr/bin/env python3

import os
from Crypto.PublicKey import ECC
from encryption_utils import generate_dh_keypair, export_key

print("Testing key generation...")

try:
    # Test X25519 key generation
    print("Generating X25519 keypair...")
    priv_key, pub_key = generate_dh_keypair()
    print("✅ X25519 keypair generated successfully")
    
    # Test key export
    print("Exporting keys...")
    priv_key_pem = export_key(priv_key)
    pub_key_pem = export_key(pub_key)
    print("✅ Keys exported successfully")
    
    # Test Ed25519 key generation
    print("Generating Ed25519 keypair...")
    sign_priv = ECC.generate(curve='Ed25519')
    sign_pub = sign_priv.public_key()
    print("✅ Ed25519 keypair generated successfully")
    
    # Test Ed25519 key export
    print("Exporting Ed25519 keys...")
    sign_priv_pem = sign_priv.export_key(format='PEM')
    sign_pub_pem = sign_pub.export_key(format='PEM')
    print("✅ Ed25519 keys exported successfully")
    
    # Test directory creation
    print("Creating keys directory...")
    os.makedirs('./keys/', exist_ok=True)
    print("✅ Keys directory created/verified")
    
    print("All key generation tests passed!")
    
except Exception as e:
    print(f"❌ Error during key generation: {e}")
    print(f"Error type: {type(e).__name__}")
    import traceback
    traceback.print_exc()
