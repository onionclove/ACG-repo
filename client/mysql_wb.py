# Jingkai

import os
from dotenv import load_dotenv
import pymysql

# Load .env from current directory first, then project root
ENV_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '.env'))
load_dotenv(ENV_PATH)

# Also try loading from project root (one level up from /client)
ENV_PATH_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '.env'))
load_dotenv(ENV_PATH_ROOT)

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
    connect_timeout=10,
    autocommit=True,
    charset='utf8mb4',
)

def _connect_no_db():
    return pymysql.connect(**CONNECT_KW)

def _connect_with_db():
    return pymysql.connect(database=DB_NAME, **CONNECT_KW)

def ensure_database():
    conn = _connect_no_db()
    try:
        c = conn.cursor()
        # backticks to avoid weird names
        c.execute(f"CREATE DATABASE IF NOT EXISTS `{DB_NAME}` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
        conn.commit()
    finally:
        conn.close()

def get_conn():
    ensure_database()
    return _connect_with_db()

def _exec(cursor, sql):
    """Small helper so if something breaks, you see exactly what."""
    try:
        cursor.execute(sql)
    except pymysql.Error as e:
        raise RuntimeError(f"MySQL error {e.errno} on SQL:\n{sql}\n{e.msg}") from e

def ensure_tables():
    ensure_database()
    conn = _connect_with_db()
    try:
        c = conn.cursor()

        # users table (identity + public keys)
        _exec(c, """
            CREATE TABLE IF NOT EXISTS users (
                username           VARCHAR(255) PRIMARY KEY,
                salt               VARBINARY(16) NOT NULL,
                hash               VARBINARY(32) NOT NULL,     -- PBKDF2-HMAC-SHA256(32 bytes)
                public_key         LONGBLOB NOT NULL,
                signing_public_key LONGBLOB NOT NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)

        # online presence
        _exec(c, """
            CREATE TABLE IF NOT EXISTS online_users (
                username   VARCHAR(255) PRIMARY KEY,
                ip_address VARCHAR(255) NOT NULL,
                port       INT NOT NULL,
                updated_on TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                           ON UPDATE CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)

        # offline records (last seen)
        _exec(c, """
            CREATE TABLE IF NOT EXISTS offline_users (
                username    VARCHAR(255) PRIMARY KEY,
                last_offline TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                              ON UPDATE CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)

        # pending messages queue (recipient offline)
        # use VARCHAR instead of ENUM to avoid version-specific SQL issues
        _exec(c, """
            CREATE TABLE IF NOT EXISTS pending_messages (
                id         BIGINT AUTO_INCREMENT PRIMARY KEY,
                recipient  VARCHAR(255) NOT NULL,
                sender     VARCHAR(255) NOT NULL,
                msg_type   VARCHAR(8)   NOT NULL,  -- 'text' or 'file'
                payload    MEDIUMBLOB   NOT NULL,  -- JSON bundle as bytes
                delivered  TINYINT(1)   DEFAULT 0,
                queued_on  TIMESTAMP    DEFAULT CURRENT_TIMESTAMP,
                INDEX (recipient),
                INDEX (delivered)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)

        # message history (optional)
        _exec(c, """
            CREATE TABLE IF NOT EXISTS messages (
                msg_id            CHAR(64) PRIMARY KEY,   -- SHA-256 hex
                sender            VARCHAR(255) NOT NULL,
                recipient         VARCHAR(255) NOT NULL,
                ts                BIGINT NOT NULL,
                nonce_base64      TEXT NOT NULL,
                tag_base64        TEXT NOT NULL,
                ct_base64         LONGTEXT NOT NULL,
                signature_base64  TEXT NOT NULL,
                INDEX idx_msg_peer_ts (recipient, ts),
                INDEX idx_msg_thread_ts (sender, recipient, ts)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)

        conn.commit()
    finally:
        conn.close()

def q(sql: str) -> str:
    """Translate SQLite-style '?' placeholders to MySQL '%s'."""
    return sql.replace("?", "%s")
