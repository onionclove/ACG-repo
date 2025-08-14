# Relay System Implementation Summary

This document summarizes the changes made to refactor your ACG messaging app to support relay mode for EC2 hosting.

## Files Created

### New Files
1. **`relay_server.py`** - TCP fan-out relay server that handles message routing
2. **`env.server.example`** - Environment template for EC2 server
3. **`env.client.example`** - Environment template for client laptops
4. **`setup_ec2.sh`** - Automated setup script for EC2 Ubuntu instance
5. **`requirements.txt`** - Python dependencies
6. **`test_relay.py`** - Test script to verify relay functionality
7. **`EC2_SETUP_README.md`** - Comprehensive setup guide
8. **`RELAY_CHANGES.md`** - This summary document

## Files Modified

### `backend.py`
- **Added**: Relay configuration variables (`USE_RELAY`, `RELAY_HOST`, `RELAY_PORT`)
- **Added**: `RelayClient` class for managing relay connections
- **Modified**: `start_receiver()` to support both relay and direct modes
- **Modified**: `stop_receiver()` to handle relay cleanup
- **Modified**: All send functions (`send_text_message`, `send_text_message_pfs`, `send_encrypted_file`) to use relay when enabled

### `mysql_wb.py`
- **Modified**: Environment file loading to check both current directory and project root

## Key Changes Explained

### 1. Relay Client Class
The `RelayClient` class maintains a persistent TCP connection to the relay server:
- Connects once and stays connected
- Thread-safe sending with locks
- Handles incoming messages in a separate thread
- Automatic reconnection handling

### 2. Dual Mode Support
The app now supports two modes:
- **Relay Mode** (`USE_RELAY=true`): All traffic goes through EC2 relay
- **Direct Mode** (`USE_RELAY=false`): Original peer-to-peer behavior

### 3. Message Flow Changes
**Before (Direct Mode)**:
```
Client A ──→ Client B (direct TCP)
```

**After (Relay Mode)**:
```
Client A ──→ Relay Server ──→ Client B
```

### 4. Security Preserved
- All encryption/decryption happens on client side
- Relay only sees encrypted bundles
- Perfect Forward Secrecy maintained
- Digital signatures still verified

## Environment Variables

### Server (EC2) Configuration
```bash
DB_HOST=127.0.0.1
DB_USER=acgapp
DB_PASSWORD=1Qwer$#@!
DB_DATABASE=acg
DB_PORT=3306
RELAY_HOST=0.0.0.0
RELAY_PORT=7000
USE_RELAY=true
```

### Client Configuration
```bash
DB_HOST=<EC2_PUBLIC_IP>
DB_USER=acgapp
DB_PASSWORD=1Qwer$#@!
DB_DATABASE=acg
DB_PORT=3306
RELAY_HOST=<EC2_PUBLIC_IP>
RELAY_PORT=7000
USE_RELAY=true
```

## Deployment Steps

### 1. EC2 Setup
```bash
# SSH to EC2
ssh -i your-key.pem ubuntu@your-ec2-ip

# Clone and setup
git clone <your-repo>
cd ACG-repo/client
chmod +x setup_ec2.sh
./setup_ec2.sh

# Start relay
source .venv/bin/activate
python init_tables.py
python relay_server.py
```

### 2. Client Setup
```bash
# On each laptop
git clone <your-repo>
cd ACG-repo/client
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -r requirements.txt

# Configure
cp env.client.example .env
# Edit .env with your EC2 IP

# Run
python gui.py
```

## Testing

Run the test script to verify relay functionality:
```bash
python test_relay.py
```

## Benefits

1. **NAT/Firewall Bypass**: No need for port forwarding
2. **Centralized Infrastructure**: Single EC2 instance serves all clients
3. **Offline Message Queuing**: Relay stores messages for offline users
4. **Scalable**: Can handle multiple simultaneous users
5. **Backward Compatible**: Original direct mode still works

## Security Considerations

- MySQL is configured to accept connections from anywhere (0.0.0.0/0)
- Consider restricting MySQL access to specific IP ranges for production
- Relay server has no authentication (relies on message encryption)
- All sensitive data remains encrypted end-to-end

## Troubleshooting

- **Connection refused**: Check EC2 security group rules
- **MySQL errors**: Verify database is running and accessible
- **Relay not working**: Ensure relay server is running on EC2
- **Environment issues**: Check .env file location and syntax

## Next Steps

1. Deploy to EC2 following the setup guide
2. Test with multiple clients
3. Monitor relay server logs
4. Consider adding authentication to relay server
5. Implement automatic relay reconnection
