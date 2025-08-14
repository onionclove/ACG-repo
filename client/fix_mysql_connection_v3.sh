#!/bin/bash

echo "Fixing MySQL connection issues (v3) - MySQL 8.0 compatible..."

# Install net-tools if not present
sudo apt install -y net-tools

# Stop MySQL
sudo systemctl stop mysql

# Configure MySQL to accept external connections
echo "Configuring MySQL to accept external connections..."
sudo sed -i 's/^bind-address.*/bind-address = 0.0.0.0/' /etc/mysql/mysql.conf.d/mysqld.cnf

# Start MySQL
sudo systemctl start mysql

# Wait for MySQL to start
echo "Waiting for MySQL to start..."
sleep 5

# Check if MySQL is running
if ! sudo systemctl is-active --quiet mysql; then
    echo "❌ MySQL failed to start!"
    sudo systemctl status mysql
    exit 1
fi

# Create database and user with MySQL 8.0 compatible authentication
echo "Creating database and user with MySQL 8.0 compatible authentication..."
sudo mysql -uroot <<'SQL'
DROP DATABASE IF EXISTS acg;
CREATE DATABASE acg;
DROP USER IF EXISTS 'acgapp'@'localhost';
DROP USER IF EXISTS 'acgapp'@'%';

-- Create users with mysql_native_password for better compatibility
CREATE USER 'acgapp'@'localhost' IDENTIFIED WITH mysql_native_password BY '1Qwer$#@!';
CREATE USER 'acgapp'@'%' IDENTIFIED WITH mysql_native_password BY '1Qwer$#@!';

GRANT ALL PRIVILEGES ON acg.* TO 'acgapp'@'localhost';
GRANT ALL PRIVILEGES ON acg.* TO 'acgapp'@'%';
FLUSH PRIVILEGES;
SQL

# Verify user creation
echo "Verifying user creation..."
sudo mysql -uroot -e "SELECT User, Host, plugin FROM mysql.user WHERE User = 'acgapp';"

# Disable UFW firewall temporarily
sudo ufw disable

# Test local connection
echo "Testing local MySQL connection..."
if mysql -uacgapp -p1Qwer$#@! -h127.0.0.1 acg -e "SELECT 1;" 2>/dev/null; then
    echo "✅ Local MySQL connection successful!"
else
    echo "❌ Local MySQL connection failed!"
    echo "Trying alternative authentication..."
    
    # Try with explicit host
    if mysql -uacgapp -p1Qwer$#@! -hlocalhost acg -e "SELECT 1;" 2>/dev/null; then
        echo "✅ Local MySQL connection successful with localhost!"
    else
        echo "❌ Local MySQL connection still failed!"
        sudo mysql -uroot -e "SHOW GRANTS FOR 'acgapp'@'localhost';"
    fi
fi

# Test external connection
echo "Testing external MySQL connection..."
EXTERNAL_IP=$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)
if mysql -uacgapp -p1Qwer$#@! -h$EXTERNAL_IP acg -e "SELECT 1;" 2>/dev/null; then
    echo "✅ External MySQL connection successful!"
else
    echo "❌ External MySQL connection failed!"
fi

# Show current configuration
echo ""
echo "Current MySQL bind-address:"
sudo cat /etc/mysql/mysql.conf.d/mysqld.cnf | grep bind-address

echo ""
echo "MySQL status:"
sudo systemctl status mysql --no-pager

echo ""
echo "MySQL listening on:"
sudo netstat -tlnp | grep 3306

echo ""
echo "Public IP (for classmates to use):"
curl -s ifconfig.me

echo ""
echo "Security group reminder: Make sure port 3306 is open in AWS security group!"
echo "Add inbound rule: Type=MySQL/Aurora, Port=3306, Source=0.0.0.0/0"

echo ""
echo "Next steps:"
echo "1. Update Python packages: pip install -r requirements.txt"
echo "2. Initialize database: python init_tables.py"
echo "3. Start relay server: python relay_server.py"
