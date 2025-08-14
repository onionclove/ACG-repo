# ACG Messaging App - EC2 Relay Setup

This guide will help you set up your ACG messaging app on an EC2 instance so your classmates can connect and chat from anywhere.

## Prerequisites

- An AWS EC2 Ubuntu instance running
- Your ACG-repo codebase
- Basic knowledge of AWS and SSH

## Step 1: AWS Security Group Configuration

Add these inbound rules to your EC2 instance's security group:

1. **SSH (Port 22)**: From your IP only
2. **Relay (Port 7000)**: From 0.0.0.0/0 (allows classmates to connect)
3. **MySQL (Port 3306)**: From 0.0.0.0/0 (simplest for demo; remove after class)

## Step 2: EC2 Setup

SSH into your EC2 instance and run:

```bash
# Clone your repo (or upload your code)
git clone https://github.com/<your-username>/ACG-repo.git
cd ACG-repo/client

# Make setup script executable and run it
chmod +x setup_ec2.sh
./setup_ec2.sh
```

The setup script will:
- Install MySQL and configure it for external connections
- Create the database and user
- Set up Python virtual environment
- Install required packages
- Create the server environment file

## Step 3: Start the Relay Server

On your EC2 instance:

```bash
cd ACG-repo/client
source .venv/bin/activate

# Initialize database tables
python init_tables.py

# Start the relay server (keep this running)
python relay_server.py
```

**Important**: Keep the relay server running. Use `tmux` or `screen` for persistent sessions:

```bash
# Using tmux
tmux new-session -d -s relay 'source .venv/bin/activate && python relay_server.py'

# Or using screen
screen -S relay
source .venv/bin/activate
python relay_server.py
# Press Ctrl+A, then D to detach
```

## Step 4: Client Setup (for classmates)

Each classmate should:

1. **Clone the repo**:
   ```bash
   git clone https://github.com/<your-username>/ACG-repo.git
   cd ACG-repo/client
   ```

2. **Set up Python environment**:
   ```bash
   python -m venv .venv
   # On Windows:
   .venv\Scripts\activate
   # On macOS/Linux:
   source .venv/bin/activate
   
   pip install -r requirements.txt
   ```

3. **Configure environment**:
   ```bash
   # Copy the client template
   cp env.client.example .env
   
   # Edit .env and replace <YOUR_EC2_PUBLIC_IP> with your actual EC2 public IP
   # You can find this in the AWS console or by running: curl ifconfig.me
   ```

4. **Run the app**:
   ```bash
   python gui.py
   ```

## How It Works

### Relay Mode vs Direct Mode

- **Relay Mode** (`USE_RELAY=true`): All messages go through your EC2 relay server
- **Direct Mode** (`USE_RELAY=false`): Messages are sent directly between clients (LAN only)

### Security

- **End-to-end encryption**: The relay cannot decrypt messages
- **Perfect Forward Secrecy**: Each message uses a new ephemeral key
- **Digital signatures**: All messages are signed to prevent tampering

### Architecture

```
Classmate 1 ──┐
Classmate 2 ──┼── EC2 Relay Server ── MySQL Database
Classmate 3 ──┘
```

## Troubleshooting

### Common Issues

1. **Connection refused**: Check security group rules
2. **MySQL connection failed**: Verify database is running and accessible
3. **Relay not working**: Ensure relay server is running on EC2

### Debug Commands

```bash
# Check if relay is listening
netstat -tlnp | grep 7000

# Check MySQL status
sudo systemctl status mysql

# Check firewall rules
sudo ufw status
```

### Logs

- Relay server logs are printed to console
- Check MySQL logs: `sudo tail -f /var/log/mysql/error.log`

## Security Notes

- The current setup allows MySQL connections from anywhere (0.0.0.0/0)
- For production, restrict MySQL to specific IP ranges
- Consider using AWS RDS instead of self-hosted MySQL
- Regularly update your EC2 instance and dependencies

## Cost Optimization

- Use EC2 t3.micro for small classes (free tier eligible)
- Stop the instance when not in use
- Consider using AWS Lambda for the relay for serverless operation

## Support

If you encounter issues:
1. Check the troubleshooting section above
2. Verify all environment variables are set correctly
3. Ensure the relay server is running and accessible
4. Check AWS security group configurations
