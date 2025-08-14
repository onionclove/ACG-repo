# relay_server.py
import socket, threading, json, queue, os
HOST = os.getenv("RELAY_HOST", "0.0.0.0")
PORT = int(os.getenv("RELAY_PORT", "7000"))

clients = {}          # username -> socket
mailbox = {}          # username -> Queue of pending bytes

def client_thread(conn):
    user = None
    try:
        hello = conn.recv(4096).decode()
        hello = json.loads(hello)  # {"hello": "username"}
        user = hello.get("hello")
        if not user:
            conn.close(); return

        clients[user] = conn
        mailbox.setdefault(user, queue.Queue())

        # flush queued
        while not mailbox[user].empty():
            conn.sendall(mailbox[user].get())

        # loop for messages from this client
        while True:
            data = conn.recv(1<<16)
            if not data:
                break
            # expected: {"to":"bob","payload":{...bundle...}}
            try:
                msg = json.loads(data.decode())
                to = msg.get("to")
                payload = json.dumps(msg.get("payload")).encode()
                if to in clients:
                    clients[to].sendall(payload)
                else:
                    mailbox.setdefault(to, queue.Queue()).put(payload)
            except Exception:
                pass
    finally:
        # cleanup
        try: conn.close()
        except: pass
        if user and clients.get(user) is conn:
            del clients[user]

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen()
    print(f"Relay listening on {HOST}:{PORT}")
    while True:
        c, _ = s.accept()
        threading.Thread(target=client_thread, args=(c,), daemon=True).start()

if __name__ == "__main__":
    main()
