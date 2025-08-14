#!/usr/bin/env python3
"""
Simple test script to verify relay functionality.
Run this after starting the relay server to test basic connectivity.
"""

import socket
import json
import threading
import time

def test_relay_connection():
    """Test basic connection to relay server"""
    try:
        # Connect to relay
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('127.0.0.1', 7000))
        
        # Send hello
        hello = {"hello": "testuser"}
        s.sendall(json.dumps(hello).encode())
        
        print("✓ Successfully connected to relay server")
        s.close()
        return True
    except Exception as e:
        print(f"✗ Failed to connect to relay: {e}")
        return False

def test_relay_message():
    """Test sending a message through relay"""
    try:
        # Connect as sender
        sender = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sender.connect(('127.0.0.1', 7000))
        sender.sendall(json.dumps({"hello": "sender"}).encode())
        
        # Connect as receiver
        receiver = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        receiver.connect(('127.0.0.1', 7000))
        receiver.sendall(json.dumps({"hello": "receiver"}).encode())
        
        # Send message from sender to receiver
        message = {"to": "receiver", "payload": {"type": "text", "message": "Hello from sender!"}}
        sender.sendall(json.dumps(message).encode())
        
        # Wait for message to arrive
        receiver.settimeout(2)
        data = receiver.recv(1024)
        if data:
            received = json.loads(data.decode())
            print(f"✓ Message relayed successfully: {received}")
            success = True
        else:
            print("✗ No message received")
            success = False
            
        sender.close()
        receiver.close()
        return success
    except Exception as e:
        print(f"✗ Failed to test message relay: {e}")
        return False

if __name__ == "__main__":
    print("Testing relay server...")
    print("Make sure relay_server.py is running first!")
    print()
    
    # Test connection
    if test_relay_connection():
        print()
        # Test message relay
        test_relay_message()
    else:
        print("\nPlease start the relay server first:")
        print("python relay_server.py")
