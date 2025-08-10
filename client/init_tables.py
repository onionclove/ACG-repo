# Run this with python init_tables.py --force to reset tables
# Or python init_tables.py to see what would happen (dry-run).
"""
Safely reset and recreate MySQL tables for the chat app.

Usage:
  python init_tables.py                 # dry-run (shows what *would* happen)
  python init_tables.py --force         # actually drop & recreate all tables
  python init_tables.py --force --seed  # reset, then create a couple test users

Notes:
- Uses your existing mysql_wb.py for connection/env.
- Matches the latest schema you’re using in backend.py/mysql_wb.py.
"""

import sys
import argparse
from typing import List
import mysql_wb  # your helper
from mysql_wb import get_conn, ensure_database

TABLES_IN_ORDER = [
    # drop in dependency-friendly order
    "messages",
    "pending_messages",
    "offline_users",
    "online_users",
    "users",
]

CREATE_STMTS = [
    # users (long-term identity + keys)
    """
    CREATE TABLE IF NOT EXISTS users (
        username VARCHAR(255) PRIMARY KEY,
        salt VARBINARY(16),
        hash VARBINARY(64),
        public_key BLOB,
        signing_public_key BLOB
    )
    """,
    # online presence (ephemeral)
    """
    CREATE TABLE IF NOT EXISTS online_users (
        username VARCHAR(255) PRIMARY KEY,
        ip_address VARCHAR(255) NOT NULL,
        port INT NOT NULL,
        updated_on TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            ON UPDATE CURRENT_TIMESTAMP
    )
    """,
    # offline marker
    """
    CREATE TABLE IF NOT EXISTS offline_users (
        username VARCHAR(255) PRIMARY KEY,
        last_offline TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            ON UPDATE CURRENT_TIMESTAMP
    )
    """,
    # offline queue (encrypted JSON bundle in payload)
    """
    CREATE TABLE IF NOT EXISTS pending_messages (
        id BIGINT AUTO_INCREMENT PRIMARY KEY,
        recipient VARCHAR(255) NOT NULL,
        sender VARCHAR(255) NOT NULL,
        msg_type ENUM('text','file') NOT NULL,
        payload MEDIUMBLOB NOT NULL,
        delivered TINYINT(1) DEFAULT 0,
        queued_on TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX(recipient),
        INDEX(delivered)
    )
    """,
    # history/journal (works with _store_message_bundle)
    """
    CREATE TABLE IF NOT EXISTS messages (
        msg_id VARCHAR(64) PRIMARY KEY,           -- SHA-256 hex of deterministic tuple
        sender VARCHAR(255) NOT NULL,
        recipient VARCHAR(255) NOT NULL,
        ts BIGINT NOT NULL,
        dir ENUM('in','out') NOT NULL,            -- direction relative to *current user*
        pfs TINYINT(1) DEFAULT 0,                 -- 1 if PFS bundle
        eph_pub_base64 TEXT,                      -- sender's ephemeral public (PFS)
        nonce_base64 TEXT NOT NULL,
        tag_base64 TEXT NOT NULL,
        ct_base64 LONGTEXT NOT NULL,
        signature_base64 TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS sent_messages (
        id BIGINT AUTO_INCREMENT PRIMARY KEY,
        sender      VARCHAR(255) NOT NULL,
        recipient   VARCHAR(255) NOT NULL,
        ts          BIGINT NOT NULL,
        plaintext   LONGTEXT NOT NULL,
        INDEX idx_sent_pair_ts (sender, recipient, ts)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """
]

INDEXES = [
    ("messages", "idx_msg_thread_ts", "CREATE INDEX idx_msg_thread_ts ON messages (sender, recipient, ts)"),
    ("messages", "idx_msg_recipient_ts", "CREATE INDEX idx_msg_recipient_ts ON messages (recipient, ts)"),
]

def ensure_index(cursor, table: str, index: str) -> None:
    cursor.execute("""
        SELECT EXISTS(
            SELECT 1 FROM information_schema.statistics
            WHERE table_schema = DATABASE()
              AND table_name = %s
              AND index_name = %s
        )
    """, (table, index))
    exists = bool(cursor.fetchone()[0])
    if not exists:
        for t, idx, sql in INDEXES:
            if t == table and idx == index:
                cursor.execute(sql)

def drop_tables(cursor, tables: List[str], dry_run: bool) -> None:
    for t in tables:
        if dry_run:
            print(f"DRY-RUN: DROP TABLE IF EXISTS {t}")
        else:
            cursor.execute(f"DROP TABLE IF EXISTS {t}")

def create_schema(cursor, dry_run: bool) -> None:
    for sql in CREATE_STMTS:
        if dry_run:
            print("DRY-RUN:", " ".join(sql.split()))
        else:
            cursor.execute(sql)

    # indexes
    if dry_run:
        for _, idx, sql in INDEXES:
            print("DRY-RUN:", sql)
    else:
        for table, idx, _ in INDEXES:
            ensure_index(cursor, table, idx)

def seed_sample_users():
    """
    Optional: create a couple of sample users using backend.register_user
    so keys are generated and stored on disk as well.
    """
    try:
        from backend import register_user
        for u in [("alice", "Alice$123"), ("bob", "Bob$12345")]:
            try:
                register_user(*u)
                print(f"  • seeded: {u[0]}")
            except Exception as e:
                print(f"  • seed skip {u[0]}: {e}")
    except Exception as e:
        print("Seeding failed (backend.register_user not available?):", e)

def main():
    parser = argparse.ArgumentParser(description="Reset and recreate MySQL tables for the chat app.")
    parser.add_argument("--force", action="store_true", help="Actually drop & recreate tables (no --force = dry run).")
    parser.add_argument("--seed", action="store_true", help="After reset, create a couple test users.")
    args = parser.parse_args()

    ensure_database()
    conn = get_conn()
    try:
        c = conn.cursor()

        print("Found DB. About to reset tables:")
        for t in TABLES_IN_ORDER:
            print("  -", t)

        if not args.force:
            print("\n⚠️  DRY-RUN: No changes made. Re-run with --force to apply.")
            # Show the SQL we'd run
            drop_tables(c, TABLES_IN_ORDER, dry_run=True)
            create_schema(c, dry_run=True)
            conn.close()
            return

        # Do it for real
        drop_tables(c, TABLES_IN_ORDER, dry_run=False)
        create_schema(c, dry_run=False)
        conn.commit()
        print("Tables dropped & recreated.")

    finally:
        try:
            conn.close()
        except Exception:
            pass

    if args.seed:
        print("🌱 Seeding sample users …")
        seed_sample_users()
        print("Seeding done.")

if __name__ == "__main__":
    main()
