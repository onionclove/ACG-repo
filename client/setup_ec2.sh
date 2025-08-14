#!/bin/bash

# EC2 Setup Script for ACG Messaging App
# Run this on your Ubuntu EC2 instance

echo "Setting up ACG Messaging App on EC2..."

# Update system
sudo apt update

# Install MySQL
echo "Installing MySQL..."
sudo apt install -y mysql-server

# Configure MySQL to accept external connections
echo "Configuring MySQL..."
sudo sed -i 's/^bind-address.*/bind-address = 0.0.0.0/' /etc/mysql/mysql.conf.d/mysqld.cnf
sudo systemctl restart mysql

# Create database and user
echo "Creating database and user..."
sudo mysql -uroot <<'SQL'
CREATE DATABASE IF NOT EXISTS acg;
CREATE USER IF NOT EXISTS 'acgapp'@'%' IDENTIFIED BY '1Qwer$#@!';
GRANT ALL PRIVILEGES ON acg.* TO 'acgapp'@'%';
FLUSH PRIVILEGES;
SQL

# Install Python dependencies
echo "Installing Python dependencies..."
sudo apt install -y python3-venv python3-pip

# Create virtual environment
echo "Setting up Python virtual environment..."
python3 -m venv .venv
source .venv/bin/activate

# Install Python packages
pip install -r requirements.txt

# Create .env file from template
echo "Creating environment file..."
cp env.server.example .env

echo "EC2 setup complete!"
echo ""
echo "Next steps:"
echo "1. Start the relay server: source .venv/bin/activate && python relay_server.py"
echo "2. Initialize database tables: python init_tables.py"
echo "3. Share your EC2 public IP with classmates"
echo "4. Have classmates copy env.client.example to .env and update with your EC2 IP"
