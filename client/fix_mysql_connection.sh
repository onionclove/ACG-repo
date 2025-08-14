#!/bin/bash

echo "Fixing MySQL connection issues..."

# Stop MySQL
sudo systemctl stop mysql

# Configure MySQL to accept external connections
echo "Configuring MySQL to accept external connections..."
sudo sed -i 's/^bind-address.*/bind-address = 0.0.0.0/' /etc/mysql/mysql.conf.d/mysqld.cnf

# Start MySQL
sudo systemctl start mysql

# Wait for MySQL to start
sleep 3

# Recreate database and user
echo "Recreating database and user..."
sudo mysql -uroot <<'SQL'
DROP DATABASE IF EXISTS acg;
CREATE DATABASE acg;
DROP USER IF EXISTS 'acgapp'@'%';
CREATE USER 'acgapp'@'%' IDENTIFIED BY '1Qwer$#@!';
GRANT ALL PRIVILEGES ON acg.* TO 'acgapp'@'%';
FLUSH PRIVILEGES;
SQL

# Disable UFW firewall temporarily
sudo ufw disable

# Test the connection
echo "Testing MySQL connection..."
mysql -uacgapp -p1Qwer$#@! -h127.0.0.1 acg -e "SELECT 1;" 2>/dev/null
if [ $? -eq 0 ]; then
    echo "✅ MySQL connection successful!"
else
    echo "❌ MySQL connection failed!"
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
echo "Security group reminder: Make sure port 3306 is open in AWS security group!"
