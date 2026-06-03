import os
import sqlite3
from pathlib import Path
from typing import Iterator

from .security import hash_password, new_account_key


DATABASE_PATH = os.getenv("DATABASE_PATH", "data/mailergg.sqlite")
DEFAULT_ADMIN_EMAIL = "cookpo222@gmail.com"
DEFAULT_FIRST_USER_EMAIL = "jackmiller2@mailergg.me"


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


def _dict_factory(cursor: sqlite3.Cursor, row: tuple) -> dict:
    return {column[0]: row[index] for index, column in enumerate(cursor.description)}


def unique_account_key(db: sqlite3.Connection) -> str:
    while True:
        key = new_account_key()
        if not db.execute("SELECT 1 FROM users WHERE account_key = ?", (key,)).fetchone():
            return key


def get_db() -> Iterator[sqlite3.Connection]:
    Path(DATABASE_PATH).parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
    db.row_factory = _dict_factory
    db.execute("PRAGMA foreign_keys = ON")
    try:
        yield db
    finally:
        db.close()


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

            CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(session_token);
            CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

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

            CREATE INDEX IF NOT EXISTS idx_admin_sessions_token ON admin_sessions(session_token);
            CREATE INDEX IF NOT EXISTS idx_admin_sessions_admin ON admin_sessions(admin_id);

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

            CREATE INDEX IF NOT EXISTS idx_messages_user_received ON messages(user_id, received_at DESC);
            CREATE INDEX IF NOT EXISTS idx_messages_user_folder_received ON messages(user_id, folder, received_at DESC);

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

            CREATE INDEX IF NOT EXISTS idx_attachments_message ON attachments(message_id);
            CREATE INDEX IF NOT EXISTS idx_attachments_user ON attachments(user_id);

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
        db.execute("DROP TABLE IF EXISTS message_search")
        db.execute(
            """
            CREATE VIRTUAL TABLE message_search USING fts5(
                subject,
                sender_email,
                body
            )
            """
        )
        columns = {row[1] for row in db.execute("PRAGMA table_info(messages)").fetchall()}
        if "folder" not in columns:
            db.execute("ALTER TABLE messages ADD COLUMN folder TEXT NOT NULL DEFAULT 'inbox'")
        db.execute("UPDATE messages SET folder = 'inbox' WHERE folder IS NULL OR folder NOT IN ('inbox', 'trash')")
        user_columns = {row[1] for row in db.execute("PRAGMA table_info(users)").fetchall()}
        if "account_key" not in user_columns:
            db.execute("ALTER TABLE users ADD COLUMN account_key TEXT")
        for row in db.execute("SELECT id FROM users WHERE account_key IS NULL OR account_key = ''").fetchall():
            db.execute("UPDATE users SET account_key = ? WHERE id = ?", (unique_account_key(db), row[0]))
        db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_account_key ON users(account_key)")
        db.execute(
            """
            INSERT INTO message_search(rowid, subject, sender_email, body)
            SELECT id, subject, sender_email, body FROM messages
            """
        )
        # Existing volumes may have the old audit_logs table tied to mailbox users.
        # Recreate it without making admins mailbox entities.
        db.executescript(
            """
            PRAGMA foreign_keys = OFF;
            CREATE TABLE IF NOT EXISTS audit_logs_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                admin_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                target_user TEXT,
                timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            INSERT OR IGNORE INTO audit_logs_new (id, admin_id, action, target_user, timestamp)
                SELECT id, admin_id, action, target_user, timestamp FROM audit_logs;
            DROP TABLE audit_logs;
            ALTER TABLE audit_logs_new RENAME TO audit_logs;
            PRAGMA foreign_keys = ON;
            """
        )
        db.execute(
            """
            INSERT INTO admins (email, password_hash, display_name)
            VALUES (?, ?, ?)
            ON CONFLICT(email) DO UPDATE SET
                password_hash = excluded.password_hash,
                display_name = excluded.display_name
            """,
            (
                required_admin["email"],
                hash_password(required_admin["password"]),
                required_admin["display_name"],
            ),
        )
        db.execute(
            """
            INSERT INTO users (email, password_hash, role, status, display_name, account_key)
            VALUES (?, ?, 'user', 'active', ?, ?)
            ON CONFLICT(email) DO UPDATE SET
                password_hash = excluded.password_hash,
                role = 'user',
                status = 'active',
                display_name = excluded.display_name,
                account_key = COALESCE(users.account_key, excluded.account_key)
            """,
            (
                required_user["email"],
                hash_password(required_user["password"]),
                required_user["display_name"],
                unique_account_key(db),
            ),
        )
        db.execute(
            """
            DELETE FROM users
            WHERE role != 'user'
               OR email IN (SELECT email FROM admins)
            """
        )
        db.execute(
            """
            UPDATE sessions
            SET revoked_at = CURRENT_TIMESTAMP
            WHERE user_id = (SELECT id FROM users WHERE email = ?)
              AND revoked_at IS NULL
            """,
            (required_user["email"],),
        )
        required_user_id = db.execute("SELECT id FROM users WHERE email = ?", (required_user["email"],)).fetchone()[0]
        for folder_name in ("inbox", "trash"):
            db.execute(
                "INSERT OR IGNORE INTO user_folders (user_id, name) VALUES (?, ?)",
                (required_user_id, folder_name),
            )
        db.execute(
            """
            UPDATE admin_sessions
            SET revoked_at = CURRENT_TIMESTAMP
            WHERE admin_id = (SELECT id FROM admins WHERE email = ?)
              AND revoked_at IS NULL
            """,
            (required_admin["email"],),
        )
        db.commit()
