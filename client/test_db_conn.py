# client/test_db_conn.py
import os, socket, sys
from mysql_wb import get_conn, ensure_tables, DB_HOST, DB_PORT, DB_USER, DB_NAME

def tcp_check(host, port, timeout=3):
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.close()
        return True
    except Exception as e:
        print(f"❌ TCP connect to {host}:{port} failed: {e}")
        return False

print("ENV resolved:")
print("  DB_HOST:", DB_HOST)
print("  DB_PORT:", DB_PORT)
print("  DB_USER:", DB_USER)
print("  DB_NAME:", DB_NAME)

print("\nStep 1: Check TCP reachability...")
if not tcp_check(DB_HOST, DB_PORT):
    sys.exit(1)
print("✅ TCP OK")

try:
    print("\nStep 2: ensure_tables() ...")
    ensure_tables()
    print("✅ ensure_tables OK")

    print("\nStep 3: get_conn() and simple query ...")
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM users")
    count = c.fetchone()[0]
    conn.close()
    print("✅ Query OK. users.count =", count)
except Exception as e:
    print("❌ DB error:", repr(e))
