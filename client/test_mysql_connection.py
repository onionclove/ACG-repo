#!/usr/bin/env python3

import os
from dotenv import load_dotenv
import pymysql

# Load environment variables
load_dotenv()

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_NAME = os.getenv("DB_DATABASE")
DB_PORT = int(os.getenv("DB_PORT", "3306"))

print(f"Testing MySQL connection to {DB_HOST}:{DB_PORT}")
print(f"User: {DB_USER}")
print(f"Database: {DB_NAME}")

try:
    # Test connection
    conn = pymysql.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        port=DB_PORT,
        database=DB_NAME,
        connect_timeout=10,
        autocommit=True,
        charset='utf8mb4'
    )
    
    cursor = conn.cursor()
    cursor.execute("SELECT 1 as test")
    result = cursor.fetchone()
    
    print("✅ MySQL connection successful!")
    print(f"Test query result: {result}")
    
    # Test if tables exist
    cursor.execute("SHOW TABLES")
    tables = cursor.fetchall()
    print(f"Tables in database: {[table[0] for table in tables]}")
    
    cursor.close()
    conn.close()
    
except pymysql.Error as e:
    print(f"❌ MySQL connection failed: {e}")
    print(f"Error code: {e.args[0] if e.args else 'Unknown'}")
    
except Exception as e:
    print(f"❌ Unexpected error: {e}")
