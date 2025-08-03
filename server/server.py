import socket
import threading
from queue import Queue
import struct

class MessageServer:
    def __init__(self):
        self.host = '127.0.0.1'
        self.port = 65432
        self.message_queues = {}  # {username: Queue()}
        self.lock = threading.Lock()

    def _handle_retrieval(self, conn, metadata):
        """Handle message retrieval requests from clients"""
        try:
            username = metadata.split(":", 1)[1]
            with self.lock:
                queue = self.message_queues.get(username, Queue())
                
                if queue.empty():
                    conn.sendall(b'\x00\x00\x00\x00')  # No messages
                    return
                
                # Send all queued messages
                while not queue.empty():
                    sender, content_type, payload = queue.get()
                    
                    # Prepare response metadata
                    response_meta = f"{sender}:{content_type}".encode()
                    meta_len = struct.pack('>I', len(response_meta))
                    payload_len = struct.pack('>I', len(payload))
                    
                    # Send message
                    conn.sendall(meta_len + response_meta + payload_len + payload)
                
        except Exception as e:
            print(f"[!] Retrieval error: {e}")
        finally:
            conn.close()

    def handle_client(self, conn, addr):
        try:
            # Read metadata length (4 bytes)
            metadata_len_data = conn.recv(4)
            if not metadata_len_data or len(metadata_len_data) != 4:
                return
                
            metadata_len = struct.unpack('>I', metadata_len_data)[0]
            metadata = conn.recv(metadata_len).decode()
            
            # Check for retrieval request
            if metadata.startswith("REQUEST:"):
                self._handle_retrieval(conn, metadata)
                return
                
            # Validate message format
            parts = metadata.split(':')
            if len(parts) != 3:
                print(f"[!] Invalid metadata from {addr}: {metadata}")
                return
                
            sender, recipient, content_type = parts
            
            # Read payload length (4 bytes)
            payload_len_data = conn.recv(4)
            if not payload_len_data or len(payload_len_data) != 4:
                print(f"[!] Invalid payload length from {addr}")
                return
            payload_len = struct.unpack('>I', payload_len_data)[0]
            
            # Read payload (variable length)
            payload = b''
            while len(payload) < payload_len:
                chunk = conn.recv(min(4096, payload_len - len(payload)))
                if not chunk:
                    break
                payload += chunk
                
            if len(payload) != payload_len:
                print(f"[!] Incomplete payload from {addr}")
                return
                
            # Store message
            with self.lock:
                if recipient not in self.message_queues:
                    self.message_queues[recipient] = Queue(maxsize=100)
                self.message_queues[recipient].put((sender, content_type, payload))
                
        except Exception as e:
            print(f"[!] Error with {addr}: {str(e)}")
        finally:
            conn.close()

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
            s.listen()
            print(f"[SERVER] Listening on {self.host}:{self.port}")
            
            while True:
                conn, addr = s.accept()
                threading.Thread(target=self.handle_client, args=(conn, addr)).start()

if __name__ == "__main__":
    server = MessageServer()
    server.start()