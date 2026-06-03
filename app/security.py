import secrets
from datetime import datetime, timedelta, timezone
from email.utils import getaddresses
from typing import Optional

from passlib.context import CryptContext


pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
SESSION_DAYS = 14


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return utc_now().isoformat()


def parse_iso(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


def new_session_token() -> str:
    return secrets.token_urlsafe(48)


def new_account_key() -> str:
    return f"{secrets.randbelow(10_000_000_000):010d}"


def session_expiry() -> str:
    return (utc_now() + timedelta(days=SESSION_DAYS)).isoformat()


def normalize_email(email: Optional[str]) -> str:
    raw = (email or "").strip()
    parsed = getaddresses([raw])
    if parsed and parsed[0][1]:
        return parsed[0][1].strip().lower()
    return raw.lower()
