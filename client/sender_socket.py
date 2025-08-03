import socket
import json
from client import send_encrypted_message

# Gather sender and message info
sender = input("Your username: ").strip()
password = input("Your password: ").strip()
recipient = input("Recipient username: ").strip()
message = input("Message to send: ").strip()

# Encrypt and prepare message
bundle = send_encrypted_message(sender, password, recipient, message)

# Extract recipient's network info
recipient_ip = bundle.pop("recipient_ip")
recipient_port = int(bundle.pop("recipient_port"))

# Send over socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((recipient_ip, recipient_port))
    s.sendall(json.dumps(bundle).encode())

print(f"✅ Encrypted message sent to {recipient} at {recipient_ip}:{recipient_port}")
