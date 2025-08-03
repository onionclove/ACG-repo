from client import register_user, login_user, send_encrypted_message
from encrypt_image import encrypt_and_sign_image
from decrypt_image import decrypt_and_verify_image
from decrypt_messaging import decrypt_and_verify_message

# Test user config
username = "helloworld1"
password = "helloworld1"
recipient = "bob1"
message = "Hello Bob!"

# IP + port simulation
sender_ip = "127.0.0.1"
sender_port = 5556
recipient_ip = "127.0.0.1"
recipient_port = 5555

# Step 1: Register users (if not already)
try:
    register_user(username, password)
    register_user(recipient, password)
except Exception as e:
    print("Registration:", e)

# Step 2: Login and bind IPs
try:
    login_user(username, password, sender_ip, sender_port)
    login_user(recipient, password, recipient_ip, recipient_port)
except Exception as e:
    print("Login:", e)

# Step 3: ECC Message Encryption
print("\n--- ECC Secure Messaging ---")
msg_bundle = send_encrypted_message(username, password, recipient, message)
print("Encrypted ECC Message:", msg_bundle)

# Step 4: ECC Message Decryption
decrypted_msg = decrypt_and_verify_message(
    priv_key_path=f"./keys/{recipient}_private.enc",
    password=password,
    sender_pub_key_path=f"./keys/{username}_public.pem",
    nonce_b64=msg_bundle['nonce'],
    tag_b64=msg_bundle['tag'],
    ciphertext_b64=msg_bundle['ciphertext'],
    signature_b64=msg_bundle['signature'],
    sender_username=username
)
print("Decrypted ECC Message:", decrypted_msg)

# Step 5: Image Encryption
print("\n--- Image Encryption ---")
encrypt_and_sign_image(
    priv_key_path=f"./keys/{username}_private.enc",
    password=password,
    recipient_pub_key_path=f"./keys/{recipient}_public.pem",
    image_path="cat.png",  # Ensure this file exists
    output_path="cat.enc"
)

# Step 6: Image Decryption
success = decrypt_and_verify_image(
    priv_key_path=f"./keys/{recipient}_private.enc",
    password=password,
    sender_pub_key_path=f"./keys/{username}_public.pem",
    encrypted_image_path="cat.enc",
    output_path="cat_decrypted.png",
    sender_username=username
)
print("Image decryption success:", success)
