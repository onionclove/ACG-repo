import socket
import json
from decrypt_messaging import decrypt_and_verify_message
from client import login_user

# Get local user's identity and IP/port to register session
username = input("Your username: ").strip()
password = input("Your password: ").strip()
ip = input("Enter your current IP address: ").strip()
port = int(input("Enter the port to listen on (e.g. 5555): ").strip())

# Register yourself as online
try:
    login_user(username, password, ip, port)
except Exception as e:
    print("❌ Login failed:", e)
    exit(1)

# Start listening
host = '0.0.0.0'
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((host, port))
    s.listen()
    print(f"🟢 Listening on {ip}:{port} as {username}...")

    conn, addr = s.accept()
    with conn:
        print(f"🔔 Connection from {addr}")
        data = conn.recv(4096)
        bundle = json.loads(data.decode())

        sender = input("Sender's username (who is messaging you?): ").strip()

        try:
            message = decrypt_and_verify_message(
                priv_key_path=f"./keys/{username}_private.enc",
                password=password,
                sender_pub_key_path=f"./keys/{sender}_public.pem",
                nonce_b64=bundle["nonce"],
                tag_b64=bundle["tag"],
                ciphertext_b64=bundle["ciphertext"],
                signature_b64=bundle["signature"],
                sender_username=sender
            )
            print(f"\n💬 Message from {sender}: {message}")
        except Exception as e:
            print("❌ Decryption or verification failed:", e)
