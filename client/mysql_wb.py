# This file is used to connect the backend to mysql workbench for ankit to have a nice ui to look at
#we refactor backend and client.py to work with mysql workbench
import os
from dotenv import load_dotenv
import mysql.connector


ENV_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '.env'))
load_dotenv(ENV_PATH)

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_NAME = os.getenv("DB_DATABASE")
DB_PORT = int(os.getenv("DB_PORT", "3306"))

CONNECT_KW = dict(
    host=DB_HOST,
    user=DB_USER,
    password=DB_PASSWORD,
    port=DB_PORT,
    connection_timeout=5,
    use_pure=True,
    raise_on_warnings=False,
)

def _connect_no_db():
    return mysql.connector.connect(**CONNECT_KW)

def _connect_with_db():
    return mysql.connector.connect(database=DB_NAME, **CONNECT_KW)

def ensure_database():
    conn = _connect_no_db()
    try:
        c = conn.cursor()
        c.execute(f"CREATE DATABASE IF NOT EXISTS `{DB_NAME}`")
        conn.commit()
    finally:
        conn.close()

def get_conn():
    ensure_database()
    return _connect_with_db()

def ensure_tables():
    ensure_database()
    conn = _connect_with_db()
    try:
        c = conn.cursor()

        c.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username VARCHAR(255) PRIMARY KEY,
                salt VARBINARY(16),
                hash VARBINARY(64),
                public_key BLOB,
                signing_public_key BLOB
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS online_users (
                username VARCHAR(255) PRIMARY KEY,
                ip_address VARCHAR(255) NOT NULL,
                port INT NOT NULL,
                updated_on TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    ON UPDATE CURRENT_TIMESTAMP
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS offline_users (
                username VARCHAR(255) PRIMARY KEY,
                last_offline TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    ON UPDATE CURRENT_TIMESTAMP
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS pending_messages (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                recipient VARCHAR(255) NOT NULL,
                sender VARCHAR(255) NOT NULL,
                msg_type VARCHAR(10) NOT NULL,
                payload LONGBLOB NOT NULL,
                created_on TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                delivered TINYINT(1) DEFAULT 0
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                msg_id BINARY(32) NOT NULL UNIQUE,
                sender VARCHAR(255) NOT NULL,
                recipient VARCHAR(255) NOT NULL,
                ts BIGINT NOT NULL,
                nonce_base64 TEXT NOT NULL,
                tag_base64 TEXT NOT NULL,
                ct_base64 TEXT NOT NULL,
                signature_base64 TEXT NOT NULL
            )
        """)

        # --- create indexes if missing ---
        def ensure_index(table, index):
            c.execute("""
                SELECT EXISTS(
                    SELECT 1
                    FROM information_schema.statistics
                    WHERE table_schema = DATABASE()
                      AND table_name = %s
                      AND index_name = %s
                )
            """, (table, index))
            return bool(c.fetchone()[0])

        if not ensure_index('messages', 'idx_msg_thread_ts'):
            c.execute("CREATE INDEX idx_msg_thread_ts ON messages (sender, recipient, ts)")
        if not ensure_index('messages', 'idx_msg_peer_ts'):
            c.execute("CREATE INDEX idx_msg_peer_ts ON messages (recipient, ts)")

        conn.commit()
    finally:
        conn.close()


def q(sql: str) -> str:
    return sql.replace("?", "%s")
