import os
import sqlite3
from pathlib import Path
from typing import Iterator

from .security import hash_password, new_account_key


DATABASE_PATH = os.getenv("DATABASE_PATH", "data/mailergg.sqlite")

DEFAULT_ADMIN_EMAIL = "cookpo222@gmail.com"
DEFAULT_FIRST_USER_EMAIL = "jackmiller2@mailergg.me"


# =========================================================
# ENV + CONFIG
# =========================================================

def required_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} must be set before starting MAILERGG")
    return value


def seed_config() -> tuple[dict, dict]:
    return (
        {
            "email": os.getenv("ADMIN_EMAIL", DEFAULT_ADMIN_EMAIL).strip().lower(),
            "password": required_env("ADMIN_PASSWORD"),
            "display_name": os.getenv("ADMIN_DISPLAY_NAME", "Controller").strip() or "Controller",
        },
        {
            "email": os.getenv("FIRST_USER_EMAIL", DEFAULT_FIRST_USER_EMAIL).strip().lower(),
            "password": required_env("FIRST_USER_PASSWORD"),
            "display_name": os.getenv("FIRST_USER_DISPLAY_NAME", "Jack Miller").strip() or "Jack Miller",
        },
    )


# =========================================================
# DB CORE HELPERS
# =========================================================

def _dict_factory(cursor: sqlite3.Cursor, row: tuple) -> dict:
    return {column[0]: row[index] for index, column in enumerate(cursor.description)}


def get_db() -> Iterator[sqlite3.Connection]:
    Path(DATABASE_PATH).parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
    db.row_factory = _dict_factory
    db.execute("PRAGMA foreign_keys = ON")
    try:
        yield db
    finally:
        db.close()


def unique_account_key(db: sqlite3.Connection) -> str:
    while True:
        key = new_account_key()
        if not db.execute(
            "SELECT 1 FROM users WHERE account_key = ?",
            (key,)
        ).fetchone():
            return key


# =========================================================
# CATCH-ALL EMAIL SYSTEM (MAIN FIX)
# =========================================================

def get_or_create_user(db: sqlite3.Connection, email: str) -> int:
    """
    Catch-all mailbox system:
    ANY @mailergg.me address automatically becomes a mailbox.
    """
    email = email.lower().strip()

    user = db.execute(
        "SELECT id FROM users WHERE email = ?",
        (email,)
    ).fetchone()

    if user:
        return user["id"]

    display_name = email.split("@")[0]

    db.execute(
        """
        INSERT INTO users (email, password_hash, role, status, display_name, account_key)
        VALUES (?, '', 'user', 'active', ?, ?)
        """,
        (email, display_name, unique_account_key(db))
    )

    db.commit()

    user = db.execute(
        "SELECT id FROM users WHERE email = ?",
        (email,)
    ).fetchone()

    return user["id"]


def save_email(db: sqlite3.Connection, sender: str, recipient: str, subject: str, body: str):
    """
    MAIN EMAIL INGESTION FUNCTION
    Used by FastAPI webhook.
    """
    user_id = get_or_create_user(db, recipient)

    db.execute(
        """
        INSERT INTO messages (
            user_id,
            sender_email,
            subject,
            body,
            received_at,
            folder,
            read_status
        )
        VALUES (?, ?, ?, ?, datetime('now'), 'inbox', 0)
        """,
        (
            user_id,
            sender,
            subject,
            body
        )
    )

    db.commit()


# =========================================================
# DATABASE INITIALIZATION
# =========================================================

def init_db() -> None:
    required_admin, required_user = seed_config()

    Path(DATABASE_PATH).parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(DATABASE_PATH) as db:
        db.execute("PRAGMA foreign_keys = ON")

        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin', 'user')),
                status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'locked')),
                display_name TEXT NOT NULL,
                account_key TEXT UNIQUE
            );

            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                display_name TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                session_token TEXT NOT NULL UNIQUE,
                device_info TEXT,
                ip_address TEXT,
                expires_at TEXT NOT NULL,
                revoked_at TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS admin_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                admin_id INTEGER NOT NULL,
                session_token TEXT NOT NULL UNIQUE,
                device_info TEXT,
                ip_address TEXT,
                expires_at TEXT NOT NULL,
                revoked_at TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(admin_id) REFERENCES admins(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS user_folders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL CHECK(name IN ('inbox', 'trash')),
                UNIQUE(user_id, name),
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                sender_email TEXT NOT NULL,
                subject TEXT NOT NULL,
                body TEXT NOT NULL,
                received_at TEXT NOT NULL,
                folder TEXT NOT NULL DEFAULT 'inbox' CHECK(folder IN ('inbox', 'trash')),
                read_status INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS attachments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                original_filename TEXT NOT NULL,
                stored_filename TEXT NOT NULL UNIQUE,
                content_type TEXT,
                size_bytes INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(message_id) REFERENCES messages(id) ON DELETE CASCADE,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                admin_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                target_user TEXT,
                timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(admin_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )

        # Ensure admin exists
        db.execute(
            """
            INSERT OR IGNORE INTO admins (email, password_hash, display_name)
            VALUES (?, ?, ?)
            """,
            (
                required_admin["email"],
                hash_password(required_admin["password"]),
                required_admin["display_name"],
            ),
        )

        # Ensure default user exists
        db.execute(
            """
            INSERT OR IGNORE INTO users (email, password_hash, role, status, display_name, account_key)
            VALUES (?, ?, 'user', 'active', ?, ?)
            """,
            (
                required_user["email"],
                hash_password(required_user["password"]),
                required_user["display_name"],
                unique_account_key(db),
            ),
        )

        db.commit()
