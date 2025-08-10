from client import register_user, login_user, send_encrypted_message
from encrypt_image import encrypt_and_sign_image
from decrypt_image import decrypt_and_verify_image
from decrypt_messaging import decrypt_and_verify_message
from history import load_thread
import time
import os

# Test user config
sender = "jack"
sender_pwd = "jackpass"
recipient = "mary"
recipient_pwd = "marypass"
message = "Hello Mary, this is Jack!"

# IP + port simulation
sender_ip = "127.0.0.1"
sender_port = 5556
recipient_ip = "127.0.0.1"
recipient_port = 5555

# Step 1: Register users if not already
for user, pwd in [(sender, sender_pwd), (recipient, recipient_pwd)]:
    try:
        register_user(user, pwd)
        print(f"Registered: {user}")
    except Exception as e:
        print(f"Registration for {user}: {e}")

# Step 2: Login and bind IPs
for user, pwd, ip, port in [(sender, sender_pwd, sender_ip, sender_port),
                            (recipient, recipient_pwd, recipient_ip, recipient_port)]:
    try:
        login_user(user, pwd, ip, port)
        print(f"Logged in: {user}")
    except Exception as e:
        print(f"Login failed for {user}: {e}")

# Step 3: ECC Message Encryption
print("\n--- ECC Secure Messaging ---")
msg_bundle = send_encrypted_message(sender, sender_pwd, recipient, message)
print("Encrypted ECC Message:", msg_bundle)

# Step 4: ECC Message Decryption
try:
    decrypted_msg = decrypt_and_verify_message(
        priv_key_path=f"./keys/{recipient}_private.enc",
        password=recipient_pwd,
        sender_pub_key_path=f"./keys/{sender}_public.pem",
        nonce_b64=msg_bundle['nonce'],
        tag_b64=msg_bundle['tag'],
        ciphertext_b64=msg_bundle['ciphertext'],
        signature_b64=msg_bundle['signature'],
        sender_username=sender
    )
    print("Decrypted ECC Message:", decrypted_msg)
except Exception as e:
    print("❌ Decryption failed:", e)

# Step 5: Image Encryption
print("\n--- Image Encryption ---")
if not os.path.exists("cat.png"):
    print("⚠️  'cat.png' not found! Skipping image encryption.")
else:
    encrypt_and_sign_image(
        priv_key_path=f"./keys/{sender}_private.enc",
        password=sender_pwd,
        recipient_pub_key_path=f"./keys/{recipient}_public.pem",
        image_path="cat.png",
        output_path="cat.enc"
    )

    # Step 6: Image Decryption
    try:
        success = decrypt_and_verify_image(
            priv_key_path=f"./keys/{recipient}_private.enc",
            password=recipient_pwd,
            sender_pub_key_path=f"./keys/{sender}_public.pem",
            encrypted_image_path="cat.enc",
            output_path="cat_decrypted.png",
            sender_username=sender
        )
        print("Image decryption success:", success)
    except Exception as e:
        print("❌ Image decryption failed:", e)

if __name__ == "__main__":
    me   = input("My username: ").strip()
    pw   = input("My password: ").strip()
    peer = input("Peer username: ").strip()

    msgs = load_thread(me, pw, peer)
    print(f"\n=== Chat {me} ↔ {peer} ===")
    for ts, sender, body in msgs:
        print(f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(ts)))}  {sender}: {body}")