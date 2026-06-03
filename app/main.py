import os
import base64
import binascii
import re
import secrets
from pathlib import Path
from json import JSONDecodeError
from datetime import datetime, timezone
from sqlite3 import OperationalError
from typing import Annotated, Optional

from fastapi import Depends, FastAPI, Form, HTTPException, Request, Response, status
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlite3 import Connection

from .database import get_db, init_db
from .security import (
    hash_password,
    iso_now,
    new_account_key,
    new_session_token,
    normalize_email,
    parse_iso,
    session_expiry,
    verify_password,
)


APP_NAME = "MAILERGG"
DELETE_PIN = "6383"
SESSION_COOKIE = "mailergg_session"
ADMIN_SESSION_COOKIE = "mailergg_control"
COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "true").lower() == "true"
ATTACHMENT_DIR = Path(os.getenv("ATTACHMENT_DIR", "data/attachments"))
MAX_ATTACHMENT_BYTES = int(os.getenv("MAX_ATTACHMENT_BYTES", str(10 * 1024 * 1024)))

app = FastAPI(title=APP_NAME)
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> Response:
    if exc.status_code == 423:
        response = templates.TemplateResponse("locked.html", {"request": request}, status_code=423)
        clear_session_cookie(response)
        return response
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=getattr(exc, "headers", None))


@app.on_event("startup")
def startup() -> None:
    init_db()


def redirect(path: str) -> RedirectResponse:
    return RedirectResponse(path, status_code=status.HTTP_303_SEE_OTHER)


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else ""


def set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        max_age=60 * 60 * 24 * 14,
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, httponly=True, secure=COOKIE_SECURE, samesite="lax")


def set_admin_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        ADMIN_SESSION_COOKIE,
        token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        max_age=60 * 60 * 24 * 14,
    )


def clear_admin_session_cookie(response: Response) -> None:
    response.delete_cookie(ADMIN_SESSION_COOKIE, httponly=True, secure=COOKIE_SECURE, samesite="lax")


def unique_account_key(db: Connection) -> str:
    while True:
        key = new_account_key()
        if not db.execute("SELECT 1 FROM users WHERE account_key = ?", (key,)).fetchone():
            return key


def current_user_optional(request: Request, db: Connection = Depends(get_db)) -> Optional[dict]:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    row = db.execute(
        """
        SELECT sessions.*, users.email, users.role, users.status, users.display_name, users.account_key
        FROM sessions
        JOIN users ON users.id = sessions.user_id
        WHERE sessions.session_token = ? AND users.role = 'user'
        """,
        (token,),
    ).fetchone()
    if row and row["status"] == "locked":
        db.execute("UPDATE sessions SET revoked_at = ? WHERE session_token = ?", (iso_now(), token))
        db.commit()
        request.state.locked_account = row
        return None
    if not row or row["revoked_at"] or parse_iso(row["expires_at"]) <= datetime.now(timezone.utc):
        return None
    return row


def current_admin_optional(request: Request, db: Connection = Depends(get_db)) -> Optional[dict]:
    token = request.cookies.get(ADMIN_SESSION_COOKIE)
    if not token:
        return None
    row = db.execute(
        """
        SELECT admin_sessions.*, admins.email, admins.display_name
        FROM admin_sessions
        JOIN admins ON admins.id = admin_sessions.admin_id
        WHERE admin_sessions.session_token = ?
        """,
        (token,),
    ).fetchone()
    if not row or row["revoked_at"] or parse_iso(row["expires_at"]) <= datetime.now(timezone.utc):
        return None
    return row


def require_user(request: Request, user: Annotated[Optional[dict], Depends(current_user_optional)]) -> dict:
    if getattr(request.state, "locked_account", None):
        raise HTTPException(status_code=423, detail="Account locked")
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    return user


def require_admin(admin: Annotated[Optional[dict], Depends(current_admin_optional)]) -> dict:
    if not admin:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    return admin


def log_admin(db: Connection, admin_id: int, action: str, target_user: Optional[str] = None) -> None:
    db.execute(
        "INSERT INTO audit_logs (admin_id, action, target_user, timestamp) VALUES (?, ?, ?, ?)",
        (admin_id, action, target_user, iso_now()),
    )


def revoke_user_sessions(db: Connection, user_id: int) -> None:
    db.execute(
        "UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
        (iso_now(), user_id),
    )


def revoke_all_sessions(db: Connection) -> None:
    db.execute("UPDATE sessions SET revoked_at = ? WHERE revoked_at IS NULL", (iso_now(),))


def safe_filename(filename: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", filename.strip())[:120]
    return cleaned or "attachment"


def index_message(db: Connection, message_id: int) -> None:
    message = db.execute("SELECT id, subject, sender_email, body FROM messages WHERE id = ?", (message_id,)).fetchone()
    if not message:
        return
    db.execute("DELETE FROM message_search WHERE rowid = ?", (message_id,))
    db.execute(
        "INSERT INTO message_search(rowid, subject, sender_email, body) VALUES (?, ?, ?, ?)",
        (message["id"], message["subject"], message["sender_email"], message["body"]),
    )


def fts_query(query: str) -> str:
    words = re.findall(r"[\w@._-]+", query)
    if not words:
        return ""
    return " OR ".join(f'"{word}"' for word in words[:8])


def remove_message_indexes(db: Connection, message_ids: list[int]) -> None:
    for message_id in message_ids:
        db.execute("DELETE FROM message_search WHERE rowid = ?", (message_id,))


def delete_attachment_files(attachments: list[dict]) -> None:
    for attachment in attachments:
        path = (ATTACHMENT_DIR / attachment["stored_filename"]).resolve()
        if ATTACHMENT_DIR.resolve() in path.parents and path.exists():
            path.unlink()


def permanently_empty_user_trash(db: Connection, user_id: int) -> int:
    trashed = db.execute("SELECT id FROM messages WHERE user_id = ? AND folder = 'trash'", (user_id,)).fetchall()
    message_ids = [row["id"] for row in trashed]
    if not message_ids:
        return 0
    placeholders = ",".join("?" for _ in message_ids)
    attachments = db.execute(f"SELECT * FROM attachments WHERE message_id IN ({placeholders})", message_ids).fetchall()
    delete_attachment_files(attachments)
    remove_message_indexes(db, message_ids)
    db.execute(f"DELETE FROM messages WHERE id IN ({placeholders}) AND user_id = ?", [*message_ids, user_id])
    return len(message_ids)


def extract_payload_value(payload: dict, names: tuple[str, ...]) -> Optional[str]:
    for name in names:
        value = payload.get(name)
        if value:
            return str(value)
    return None


def parse_json_attachments(payload: dict) -> list[dict]:
    raw = payload.get("attachments") or payload.get("attachment")
    if not raw:
        return []
    if isinstance(raw, str):
        try:
            import json

            raw = json.loads(raw)
        except Exception:
            return []
    if isinstance(raw, dict):
        raw = [raw]
    if not isinstance(raw, list):
        return []
    parsed = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        filename = item.get("filename") or item.get("name") or "attachment"
        content = item.get("content") or item.get("data") or item.get("base64")
        if not content:
            continue
        parsed.append(
            {
                "filename": str(filename),
                "content_type": str(item.get("content_type") or item.get("type") or "application/octet-stream"),
                "content": str(content),
            }
        )
    return parsed


async def store_attachments(request: Request, payload: dict, message_id: int, user_id: int, db: Connection) -> None:
    ATTACHMENT_DIR.mkdir(parents=True, exist_ok=True)
    attachments: list[dict] = []
    if hasattr(request.state, "form_files"):
        attachments.extend(request.state.form_files)
    attachments.extend(parse_json_attachments(payload))
    for attachment in attachments:
        original = safe_filename(attachment["filename"])
        stored = f"{user_id}_{message_id}_{secrets.token_hex(16)}_{original}"
        destination = ATTACHMENT_DIR / stored
        if "file" in attachment:
            content = await attachment["file"].read()
        else:
            content_text = attachment["content"]
            if content_text.startswith("data:") and "," in content_text:
                content_text = content_text.split(",", 1)[1]
            try:
                content = base64.b64decode(content_text, validate=True)
            except binascii.Error:
                content = content_text.encode("utf-8")
        if not content or len(content) > MAX_ATTACHMENT_BYTES:
            continue
        destination.write_bytes(content)
        db.execute(
            """
            INSERT INTO attachments (message_id, user_id, original_filename, stored_filename, content_type, size_bytes)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                message_id,
                user_id,
                original,
                stored,
                attachment.get("content_type") or "application/octet-stream",
                len(content),
            ),
        )


def viewer_users(db: Connection) -> list[dict]:
    return db.execute(
        """
        SELECT users.id, users.email, users.display_name, users.status, COUNT(messages.id) AS message_count
        FROM users
        LEFT JOIN messages ON messages.user_id = users.id
        WHERE users.role = 'user'
        GROUP BY users.id
        ORDER BY users.email
        """
    ).fetchall()


def viewer_response(
    request: Request,
    db: Connection,
    selected_user_id: Optional[int] = None,
    message_id: Optional[int] = None,
    folder: str = "inbox",
    q: str = "",
) -> HTMLResponse:
    if folder not in {"inbox", "trash"}:
        folder = "inbox"
    users = viewer_users(db)
    selected_user = None
    messages = []
    message = None
    attachments = []
    query = q.strip()
    if selected_user_id is not None:
        selected_user = db.execute(
            "SELECT id, email, display_name, status FROM users WHERE id = ? AND role = 'user'",
            (selected_user_id,),
        ).fetchone()
        if not selected_user:
            raise HTTPException(status_code=404, detail="User not found")
    search = fts_query(query)
    if search:
        try:
            messages = db.execute(
                """
                SELECT messages.*
                FROM message_search
                JOIN messages ON messages.id = message_search.rowid
                WHERE messages.user_id = ? AND messages.folder = ? AND message_search MATCH ?
                ORDER BY messages.received_at DESC
                """,
                (selected_user_id, folder, search),
            ).fetchall()
        except OperationalError:
            messages = []
        else:
            messages = db.execute(
                "SELECT * FROM messages WHERE user_id = ? AND folder = ? ORDER BY received_at DESC",
                (selected_user_id, folder),
            ).fetchall()
        if message_id is not None:
            message = db.execute(
                "SELECT * FROM messages WHERE id = ? AND user_id = ? AND folder = ?",
                (message_id, selected_user_id, folder),
            ).fetchone()
            if not message:
                raise HTTPException(status_code=404, detail="Message not found")
            attachments = db.execute("SELECT * FROM attachments WHERE message_id = ? ORDER BY id", (message_id,)).fetchall()
    return templates.TemplateResponse(
        "viewer.html",
        {
            "request": request,
            "users": users,
            "selected_user": selected_user,
            "messages": messages,
            "message": message,
            "attachments": attachments,
            "folder": folder,
            "q": query,
            "notice": request.query_params.get("notice"),
            "error": request.query_params.get("error"),
        },
    )


def mailbox_response(
    request: Request,
    db: Connection,
    user: dict,
    folder: str = "inbox",
    message_id: Optional[int] = None,
    q: str = "",
) -> HTMLResponse:
    if folder not in {"inbox", "trash"}:
        folder = "inbox"
    query = q.strip()
    search = fts_query(query)
    if search:
        try:
            messages = db.execute(
                """
                SELECT messages.*
                FROM message_search
                JOIN messages ON messages.id = message_search.rowid
                WHERE messages.user_id = ? AND messages.folder = ? AND message_search MATCH ?
                ORDER BY messages.received_at DESC
                """,
                (user["user_id"], folder, search),
            ).fetchall()
        except OperationalError:
            messages = []
    else:
        messages = db.execute(
            "SELECT * FROM messages WHERE user_id = ? AND folder = ? ORDER BY received_at DESC",
            (user["user_id"], folder),
        ).fetchall()
    message = None
    if message_id is not None:
        message = db.execute(
            "SELECT * FROM messages WHERE id = ? AND user_id = ? AND folder = ?",
            (message_id, user["user_id"], folder),
        ).fetchone()
        if not message:
            raise HTTPException(status_code=404, detail="Message not found")
        if not message["read_status"]:
            db.execute("UPDATE messages SET read_status = 1 WHERE id = ? AND user_id = ?", (message_id, user["user_id"]))
            db.commit()
    counts = db.execute(
        """
        SELECT folder, COUNT(*) AS count
        FROM messages
        WHERE user_id = ?
        GROUP BY folder
        """,
        (user["user_id"],),
    ).fetchall()
    folder_counts = {"inbox": 0, "trash": 0}
    for row in counts:
        folder_counts[row["folder"]] = row["count"]
    return templates.TemplateResponse(
        "inbox.html",
        {
            "request": request,
            "user": user,
            "messages": messages,
            "message": message,
            "folder": folder,
            "folder_counts": folder_counts,
            "q": query,
            "attachments": db.execute("SELECT * FROM attachments WHERE message_id = ? ORDER BY id", (message_id,)).fetchall() if message else [],
        },
    )


@app.get("/", response_class=HTMLResponse)
def root(
    user: Annotated[Optional[dict], Depends(current_user_optional)],
    admin: Annotated[Optional[dict], Depends(current_admin_optional)],
) -> RedirectResponse:
    if admin:
        return redirect("/viewer")
    return redirect("/inbox" if user else "/login")


@app.get("/login", response_class=HTMLResponse)
def login_page(
    request: Request,
    user: Annotated[Optional[dict], Depends(current_user_optional)],
    admin: Annotated[Optional[dict], Depends(current_admin_optional)],
) -> HTMLResponse:
    if admin:
        return redirect("/viewer")
    if user:
        return redirect("/inbox")
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@app.post("/login")
def login(
    request: Request,
    email: Annotated[str, Form()],
    password: Annotated[str, Form()],
    db: Connection = Depends(get_db),
) -> Response:
    normalized = normalize_email(email)
    user = db.execute("SELECT * FROM users WHERE email = ? AND role = 'user'", (normalized,)).fetchone()
    if user and user["status"] == "locked" and verify_password(password, user["password_hash"]):
        revoke_user_sessions(db, user["id"])
        db.commit()
        return templates.TemplateResponse("locked.html", {"request": request}, status_code=423)
    if user and user["status"] == "active" and verify_password(password, user["password_hash"]):
        token = new_session_token()
        db.execute(
            """
            INSERT INTO sessions (user_id, session_token, device_info, ip_address, expires_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (user["id"], token, request.headers.get("user-agent", ""), client_ip(request), session_expiry()),
        )
        db.commit()
        response = redirect("/inbox")
        set_session_cookie(response, token)
        clear_admin_session_cookie(response)
        return response

    admin = db.execute("SELECT * FROM admins WHERE email = ?", (normalized,)).fetchone()
    if admin and verify_password(password, admin["password_hash"]):
        token = new_session_token()
        db.execute(
            """
            INSERT INTO admin_sessions (admin_id, session_token, device_info, ip_address, expires_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (admin["id"], token, request.headers.get("user-agent", ""), client_ip(request), session_expiry()),
        )
        db.commit()
        response = redirect("/viewer")
        set_admin_session_cookie(response, token)
        clear_session_cookie(response)
        return response

    if not user:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Invalid email or password"},
            status_code=status.HTTP_401_UNAUTHORIZED,
        )
    return templates.TemplateResponse(
        "login.html",
        {"request": request, "error": "Invalid email or password"},
        status_code=status.HTTP_401_UNAUTHORIZED,
    )


@app.post("/logout")
def logout(request: Request, db: Connection = Depends(get_db)) -> RedirectResponse:
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        db.execute("UPDATE sessions SET revoked_at = ? WHERE session_token = ?", (iso_now(), token))
    admin_token = request.cookies.get(ADMIN_SESSION_COOKIE)
    if admin_token:
        db.execute("UPDATE admin_sessions SET revoked_at = ? WHERE session_token = ?", (iso_now(), admin_token))
    if token or admin_token:
        db.commit()
    response = redirect("/login")
    clear_session_cookie(response)
    clear_admin_session_cookie(response)
    return response


@app.get("/inbox", response_class=HTMLResponse)
def inbox(
    request: Request,
    user: Annotated[dict, Depends(require_user)],
    folder: str = "inbox",
    q: str = "",
    db: Connection = Depends(get_db),
) -> HTMLResponse:
    return mailbox_response(request, db, user, folder, q=q)


@app.get("/inbox/messages/{message_id}", response_class=HTMLResponse)
def inbox_message(
    request: Request,
    message_id: int,
    user: Annotated[dict, Depends(require_user)],
    folder: str = "inbox",
    q: str = "",
    db: Connection = Depends(get_db),
) -> HTMLResponse:
    return mailbox_response(request, db, user, folder, message_id, q)


@app.get("/messages/{message_id}", response_class=HTMLResponse)
def message_view(
    request: Request,
    message_id: int,
    user: Annotated[dict, Depends(require_user)],
    db: Connection = Depends(get_db),
) -> HTMLResponse:
    message = db.execute(
        "SELECT * FROM messages WHERE id = ? AND user_id = ?",
        (message_id, user["user_id"]),
    ).fetchone()
    if not message:
        raise HTTPException(status_code=404, detail="Message not found")
    return redirect(f"/inbox/messages/{message_id}?folder={message['folder']}")


@app.post("/messages/{message_id}/read")
def mark_read(message_id: int, user: Annotated[dict, Depends(require_user)], db: Connection = Depends(get_db)) -> RedirectResponse:
    db.execute("UPDATE messages SET read_status = 1 WHERE id = ? AND user_id = ?", (message_id, user["user_id"]))
    db.commit()
    message = db.execute("SELECT folder FROM messages WHERE id = ? AND user_id = ?", (message_id, user["user_id"])).fetchone()
    folder = message["folder"] if message else "inbox"
    return redirect(f"/inbox/messages/{message_id}?folder={folder}")


@app.post("/messages/{message_id}/trash")
def move_to_trash(message_id: int, user: Annotated[dict, Depends(require_user)], db: Connection = Depends(get_db)) -> RedirectResponse:
    db.execute("UPDATE messages SET folder = 'trash' WHERE id = ? AND user_id = ?", (message_id, user["user_id"]))
    db.commit()
    return redirect("/inbox?folder=inbox")


@app.post("/messages/{message_id}/restore")
def restore_message(message_id: int, user: Annotated[dict, Depends(require_user)], db: Connection = Depends(get_db)) -> RedirectResponse:
    db.execute("UPDATE messages SET folder = 'inbox' WHERE id = ? AND user_id = ?", (message_id, user["user_id"]))
    db.commit()
    return redirect(f"/inbox/messages/{message_id}?folder=inbox")


@app.post("/trash/empty")
def empty_trash(user: Annotated[dict, Depends(require_user)], db: Connection = Depends(get_db)) -> RedirectResponse:
    permanently_empty_user_trash(db, user["user_id"])
    db.commit()
    return redirect("/inbox?folder=trash")


@app.get("/attachments/{attachment_id}")
def download_attachment(
    attachment_id: int,
    user: Annotated[dict, Depends(require_user)],
    db: Connection = Depends(get_db),
) -> FileResponse:
    attachment = db.execute("SELECT * FROM attachments WHERE id = ? AND user_id = ?", (attachment_id, user["user_id"])).fetchone()
    if not attachment:
        raise HTTPException(status_code=404, detail="Attachment not found")
    path = (ATTACHMENT_DIR / attachment["stored_filename"]).resolve()
    if ATTACHMENT_DIR.resolve() not in path.parents or not path.exists():
        raise HTTPException(status_code=404, detail="Attachment not found")
    return FileResponse(path, media_type=attachment["content_type"], filename=attachment["original_filename"])


@app.get("/viewer/attachments/{attachment_id}")
def viewer_download_attachment(
    attachment_id: int,
    admin: Annotated[dict, Depends(require_admin)],
    db: Connection = Depends(get_db),
) -> FileResponse:
    attachment = db.execute("SELECT * FROM attachments WHERE id = ?", (attachment_id,)).fetchone()
    if not attachment:
        raise HTTPException(status_code=404, detail="Attachment not found")
    path = (ATTACHMENT_DIR / attachment["stored_filename"]).resolve()
    if ATTACHMENT_DIR.resolve() not in path.parents or not path.exists():
        raise HTTPException(status_code=404, detail="Attachment not found")
    log_admin(db, admin["admin_id"], "download_attachment", attachment["original_filename"])
    db.commit()
    return FileResponse(path, media_type=attachment["content_type"], filename=attachment["original_filename"])


@app.get("/viewer", response_class=HTMLResponse)
def viewer_home(request: Request, admin: Annotated[dict, Depends(require_admin)], db: Connection = Depends(get_db)) -> HTMLResponse:
    log_admin(db, admin["admin_id"], "viewer_list_users")
    db.commit()
    return viewer_response(request, db)


@app.get("/viewer/users/{user_id}", response_class=HTMLResponse)
def viewer_user(
    request: Request,
    user_id: int,
    admin: Annotated[dict, Depends(require_admin)],
    folder: str = "inbox",
    q: str = "",
    db: Connection = Depends(get_db),
) -> HTMLResponse:
    selected_user = db.execute("SELECT id, email, display_name, status FROM users WHERE id = ? AND role = 'user'", (user_id,)).fetchone()
    if not selected_user:
        raise HTTPException(status_code=404, detail="User not found")
    log_admin(db, admin["admin_id"], "viewer_open_user", selected_user["email"])
    db.commit()
    return viewer_response(request, db, user_id, folder=folder, q=q)


@app.get("/viewer/users/{user_id}/messages/{message_id}", response_class=HTMLResponse)
def viewer_message(
    request: Request,
    user_id: int,
    message_id: int,
    admin: Annotated[dict, Depends(require_admin)],
    folder: str = "inbox",
    q: str = "",
    db: Connection = Depends(get_db),
) -> HTMLResponse:
    selected_user = db.execute("SELECT id, email, display_name, status FROM users WHERE id = ? AND role = 'user'", (user_id,)).fetchone()
    if not selected_user:
        raise HTTPException(status_code=404, detail="User not found")
    message = db.execute("SELECT * FROM messages WHERE id = ? AND user_id = ?", (message_id, user_id)).fetchone()
    if not message:
        raise HTTPException(status_code=404, detail="Message not found")
    log_admin(db, admin["admin_id"], "viewer_open_message", selected_user["email"])
    db.commit()
    return viewer_response(request, db, user_id, message_id, folder, q)


@app.post("/viewer/users")
def viewer_create_user(
    admin: Annotated[dict, Depends(require_admin)],
    email: Annotated[str, Form()],
    password: Annotated[str, Form()],
    display_name: Annotated[Optional[str], Form()] = None,
    db: Connection = Depends(get_db),
) -> RedirectResponse:
    if len(password) < 12:
        return redirect("/viewer?error=Password%20must%20be%2012%20characters")
    normalized = normalize_email(email)
    if "@" not in normalized:
        return redirect("/viewer?error=Email%20not%20accepted")
    if db.execute("SELECT 1 FROM admins WHERE email = ?", (normalized,)).fetchone():
        return redirect("/viewer?error=Address%20reserved")
    try:
        db.execute(
            "INSERT INTO users (email, password_hash, role, status, display_name, account_key) VALUES (?, ?, 'user', 'active', ?, ?)",
            (normalized, hash_password(password), display_name or normalized.split("@")[0], unique_account_key(db)),
        )
    except Exception as exc:
        if "UNIQUE" in str(exc).upper():
            return redirect("/viewer?error=User%20already%20exists")
        raise
    log_admin(db, admin["admin_id"], "create_user", normalized)
    db.commit()
    user_id = db.execute("SELECT id FROM users WHERE email = ?", (normalized,)).fetchone()["id"]
    for folder_name in ("inbox", "trash"):
        db.execute("INSERT OR IGNORE INTO user_folders (user_id, name) VALUES (?, ?)", (user_id, folder_name))
    db.commit()
    return redirect(f"/viewer/users/{user_id}?notice=Person%20created")


@app.post("/viewer/users/{user_id}/password")
def viewer_reset_password(
    user_id: int,
    admin: Annotated[dict, Depends(require_admin)],
    password: Annotated[str, Form()],
    db: Connection = Depends(get_db),
) -> RedirectResponse:
    if len(password) < 12:
        return redirect(f"/viewer/users/{user_id}?error=Password%20must%20be%2012%20characters")
    target = db.execute("SELECT * FROM users WHERE id = ? AND role = 'user'", (user_id,)).fetchone()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(password), user_id))
    revoke_user_sessions(db, user_id)
    log_admin(db, admin["admin_id"], "reset_password", target["email"])
    db.commit()
    return redirect(f"/viewer/users/{user_id}?notice=Password%20updated")


@app.post("/viewer/users/{user_id}/lock")
def viewer_lock_user(user_id: int, admin: Annotated[dict, Depends(require_admin)], db: Connection = Depends(get_db)) -> RedirectResponse:
    target = db.execute("SELECT * FROM users WHERE id = ? AND role = 'user'", (user_id,)).fetchone()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    db.execute("UPDATE users SET status = 'locked' WHERE id = ?", (user_id,))
    revoke_user_sessions(db, user_id)
    log_admin(db, admin["admin_id"], "lock_user", target["email"])
    db.commit()
    return redirect(f"/viewer/users/{user_id}?notice=Access%20locked")


@app.post("/viewer/users/{user_id}/unlock")
def viewer_unlock_user(user_id: int, admin: Annotated[dict, Depends(require_admin)], db: Connection = Depends(get_db)) -> RedirectResponse:
    target = db.execute("SELECT * FROM users WHERE id = ? AND role = 'user'", (user_id,)).fetchone()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    db.execute("UPDATE users SET status = 'active' WHERE id = ?", (user_id,))
    log_admin(db, admin["admin_id"], "unlock_user", target["email"])
    db.commit()
    return redirect(f"/viewer/users/{user_id}?notice=Access%20restored")


@app.post("/viewer/users/{user_id}/delete")
def viewer_delete_user(
    user_id: int,
    admin: Annotated[dict, Depends(require_admin)],
    pin: Annotated[str, Form()],
    db: Connection = Depends(get_db),
) -> RedirectResponse:
    target = db.execute("SELECT * FROM users WHERE id = ? AND role = 'user'", (user_id,)).fetchone()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    if pin != DELETE_PIN:
        return redirect(f"/viewer/users/{user_id}?error=PIN%20not%20accepted")
    revoke_user_sessions(db, user_id)
    attachments = db.execute("SELECT * FROM attachments WHERE user_id = ?", (user_id,)).fetchall()
    delete_attachment_files(attachments)
    message_ids = [row["id"] for row in db.execute("SELECT id FROM messages WHERE user_id = ?", (user_id,)).fetchall()]
    remove_message_indexes(db, message_ids)
    db.execute("DELETE FROM messages WHERE user_id = ?", (user_id,))
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    log_admin(db, admin["admin_id"], "delete_user", target["email"])
    db.commit()
    return redirect("/viewer?notice=Person%20removed")


@app.post("/viewer/users/{user_id}/trash/empty")
def viewer_empty_user_trash(user_id: int, admin: Annotated[dict, Depends(require_admin)], db: Connection = Depends(get_db)) -> RedirectResponse:
    target = db.execute("SELECT * FROM users WHERE id = ? AND role = 'user'", (user_id,)).fetchone()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    count = permanently_empty_user_trash(db, user_id)
    log_admin(db, admin["admin_id"], "empty_trash", target["email"])
    db.commit()
    return redirect(f"/viewer/users/{user_id}?folder=trash&notice={count}%20removed")


@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, user: Annotated[dict, Depends(require_user)]) -> HTMLResponse:
    return templates.TemplateResponse("settings.html", {"request": request, "user": user, "notice": None, "error": None})


@app.post("/settings/profile", response_class=HTMLResponse)
def update_profile(
    request: Request,
    display_name: Annotated[str, Form()],
    user: Annotated[dict, Depends(require_user)],
    db: Connection = Depends(get_db),
) -> HTMLResponse:
    cleaned = display_name.strip()[:80]
    if not cleaned:
        return templates.TemplateResponse("settings.html", {"request": request, "user": user, "notice": None, "error": "Display name is required"})
    db.execute("UPDATE users SET display_name = ? WHERE id = ?", (cleaned, user["user_id"]))
    db.commit()
    updated = dict(user)
    updated["display_name"] = cleaned
    return templates.TemplateResponse("settings.html", {"request": request, "user": updated, "notice": "Saved", "error": None})


@app.post("/settings/password", response_class=HTMLResponse)
def update_password(
    request: Request,
    current_password: Annotated[str, Form()],
    new_password: Annotated[str, Form()],
    user: Annotated[dict, Depends(require_user)],
    db: Connection = Depends(get_db),
) -> Response:
    account = db.execute("SELECT * FROM users WHERE id = ?", (user["user_id"],)).fetchone()
    if not verify_password(current_password, account["password_hash"]) or len(new_password) < 12:
        return templates.TemplateResponse("settings.html", {"request": request, "user": user, "notice": None, "error": "Password update failed"})
    db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(new_password), user["user_id"]))
    revoke_user_sessions(db, user["user_id"])
    db.commit()
    response = redirect("/login")
    clear_session_cookie(response)
    return response


@app.post("/webhook/email")
async def receive_email(request: Request, db: Connection = Depends(get_db)) -> JSONResponse:
    if request.headers.get("content-type", "").startswith("application/json"):
        try:
            payload = await request.json()
        except JSONDecodeError:
            raise HTTPException(status_code=400, detail="Invalid JSON payload")
    else:
        form = await request.form()
        payload = {}
        form_files = []
        for key, value in form.multi_items():
            if hasattr(value, "filename") and value.filename:
                form_files.append(
                    {
                        "filename": value.filename,
                        "content_type": value.content_type or "application/octet-stream",
                        "file": value,
                    }
                )
            else:
                payload[key] = value
        request.state.form_files = form_files

    recipient = normalize_email(
        payload.get("recipient_email")
        or payload.get("recipient")
        or payload.get("to")
        or payload.get("To")
    )
    sender = normalize_email(
        payload.get("sender_email")
        or payload.get("sender")
        or payload.get("from")
        or payload.get("From")
    )
    subject = str(payload.get("subject") or payload.get("Subject") or "(no subject)")[:500]
    body = str(
        payload.get("body")
        or payload.get("text")
        or payload.get("stripped-text")
        or payload.get("html")
        or ""
    )
    timestamp = str(payload.get("timestamp") or payload.get("received_at") or iso_now())

    if not recipient or not sender:
        raise HTTPException(status_code=422, detail="recipient_email and sender_email are required")
    user = db.execute("SELECT * FROM users WHERE email = ? AND role = 'user'", (recipient,)).fetchone()
    if not user:
        return JSONResponse({"status": "ignored", "reason": "recipient not found"}, status_code=202)
    db.execute(
        """
        INSERT INTO messages (user_id, sender_email, subject, body, received_at, folder, read_status)
        VALUES (?, ?, ?, ?, ?, 'inbox', 0)
        """,
        (user["id"], sender, subject, body, timestamp),
    )
    message_id = db.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
    index_message(db, message_id)
    await store_attachments(request, payload, message_id, user["id"], db)
    db.commit()
    return JSONResponse({"status": "stored", "recipient_email": recipient})


@app.post("/admin/users")
def admin_create_user(
    admin: Annotated[dict, Depends(require_admin)],
    email: Annotated[str, Form()],
    password: Annotated[str, Form()],
    display_name: Annotated[Optional[str], Form()] = None,
    db: Connection = Depends(get_db),
) -> JSONResponse:
    if len(password) < 12:
        raise HTTPException(status_code=422, detail="Invalid password")
    normalized = normalize_email(email)
    if "@" not in normalized:
        raise HTTPException(status_code=422, detail="Valid email is required")
    if db.execute("SELECT 1 FROM admins WHERE email = ?", (normalized,)).fetchone():
        raise HTTPException(status_code=409, detail="Address is reserved")
    try:
        db.execute(
            "INSERT INTO users (email, password_hash, role, status, display_name, account_key) VALUES (?, ?, 'user', 'active', ?, ?)",
            (normalized, hash_password(password), display_name or normalized.split("@")[0], unique_account_key(db)),
        )
    except Exception as exc:
        if "UNIQUE" in str(exc).upper():
            raise HTTPException(status_code=409, detail="User already exists")
        raise
    log_admin(db, admin["admin_id"], "create_user", normalized)
    db.commit()
    user_id = db.execute("SELECT id FROM users WHERE email = ?", (normalized,)).fetchone()["id"]
    for folder_name in ("inbox", "trash"):
        db.execute("INSERT OR IGNORE INTO user_folders (user_id, name) VALUES (?, ?)", (user_id, folder_name))
    db.commit()
    return JSONResponse({"status": "created", "email": normalized, "role": "user"}, status_code=201)


@app.delete("/admin/users/{user_id}")
def admin_delete_user(
    user_id: int,
    admin: Annotated[dict, Depends(require_admin)],
    pin: str,
    db: Connection = Depends(get_db),
) -> JSONResponse:
    if pin != DELETE_PIN:
        raise HTTPException(status_code=403, detail="Invalid deletion PIN")
    target = db.execute("SELECT * FROM users WHERE id = ? AND role = 'user'", (user_id,)).fetchone()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    revoke_user_sessions(db, user_id)
    attachments = db.execute("SELECT * FROM attachments WHERE user_id = ?", (user_id,)).fetchall()
    delete_attachment_files(attachments)
    message_ids = [row["id"] for row in db.execute("SELECT id FROM messages WHERE user_id = ?", (user_id,)).fetchall()]
    remove_message_indexes(db, message_ids)
    db.execute("DELETE FROM messages WHERE user_id = ?", (user_id,))
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    log_admin(db, admin["admin_id"], "delete_user", target["email"])
    db.commit()
    return JSONResponse({"status": "deleted", "email": target["email"]})


@app.post("/admin/users/{user_id}/password")
def admin_reset_password(
    user_id: int,
    admin: Annotated[dict, Depends(require_admin)],
    password: Annotated[str, Form()],
    db: Connection = Depends(get_db),
) -> JSONResponse:
    if len(password) < 12:
        raise HTTPException(status_code=422, detail="Password must be at least 12 characters")
    target = db.execute("SELECT * FROM users WHERE id = ? AND role = 'user'", (user_id,)).fetchone()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(password), user_id))
    revoke_user_sessions(db, user_id)
    log_admin(db, admin["admin_id"], "reset_password", target["email"])
    db.commit()
    return JSONResponse({"status": "password_reset"})


@app.post("/admin/users/{user_id}/lock")
def admin_lock_user(user_id: int, admin: Annotated[dict, Depends(require_admin)], db: Connection = Depends(get_db)) -> JSONResponse:
    target = db.execute("SELECT * FROM users WHERE id = ? AND role = 'user'", (user_id,)).fetchone()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    db.execute("UPDATE users SET status = 'locked' WHERE id = ?", (user_id,))
    revoke_user_sessions(db, user_id)
    log_admin(db, admin["admin_id"], "lock_user", target["email"])
    db.commit()
    return JSONResponse({"status": "locked"})


@app.post("/admin/users/{user_id}/unlock")
def admin_unlock_user(user_id: int, admin: Annotated[dict, Depends(require_admin)], db: Connection = Depends(get_db)) -> JSONResponse:
    target = db.execute("SELECT * FROM users WHERE id = ? AND role = 'user'", (user_id,)).fetchone()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    db.execute("UPDATE users SET status = 'active' WHERE id = ?", (user_id,))
    log_admin(db, admin["admin_id"], "unlock_user", target["email"])
    db.commit()
    return JSONResponse({"status": "unlocked"})


@app.get("/admin/users")
def admin_list_users(admin: Annotated[dict, Depends(require_admin)], db: Connection = Depends(get_db)) -> JSONResponse:
    users = db.execute("SELECT id, email, role, status, display_name FROM users WHERE role = 'user' ORDER BY email").fetchall()
    log_admin(db, admin["admin_id"], "list_users")
    db.commit()
    return JSONResponse({"users": users})


@app.get("/admin/users/{user_id}/inbox")
def admin_view_inbox(user_id: int, admin: Annotated[dict, Depends(require_admin)], folder: str = "inbox", db: Connection = Depends(get_db)) -> JSONResponse:
    if folder not in {"inbox", "trash"}:
        folder = "inbox"
    target = db.execute("SELECT id, email FROM users WHERE id = ? AND role = 'user'", (user_id,)).fetchone()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    messages = db.execute("SELECT * FROM messages WHERE user_id = ? AND folder = ? ORDER BY received_at DESC", (user_id, folder)).fetchall()
    log_admin(db, admin["admin_id"], "view_inbox", target["email"])
    db.commit()
    return JSONResponse({"user": target, "messages": messages})


@app.post("/admin/users/{user_id}/trash/empty")
def admin_empty_user_trash(user_id: int, admin: Annotated[dict, Depends(require_admin)], db: Connection = Depends(get_db)) -> JSONResponse:
    target = db.execute("SELECT id, email FROM users WHERE id = ? AND role = 'user'", (user_id,)).fetchone()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    count = permanently_empty_user_trash(db, user_id)
    log_admin(db, admin["admin_id"], "empty_trash", target["email"])
    db.commit()
    return JSONResponse({"status": "emptied", "deleted": count})


@app.get("/admin/sessions")
def admin_sessions(admin: Annotated[dict, Depends(require_admin)], db: Connection = Depends(get_db)) -> JSONResponse:
    sessions = db.execute(
        """
        SELECT sessions.id, users.email, sessions.device_info, sessions.ip_address,
               sessions.expires_at, sessions.revoked_at, sessions.created_at
        FROM sessions JOIN users ON users.id = sessions.user_id
        WHERE users.role = 'user'
        ORDER BY sessions.created_at DESC
        """
    ).fetchall()
    log_admin(db, admin["admin_id"], "view_sessions")
    db.commit()
    return JSONResponse({"sessions": sessions})


@app.post("/admin/sessions/{session_id}/revoke")
def admin_revoke_session(session_id: int, admin: Annotated[dict, Depends(require_admin)], db: Connection = Depends(get_db)) -> JSONResponse:
    session = db.execute(
        "SELECT sessions.*, users.email FROM sessions JOIN users ON users.id = sessions.user_id WHERE sessions.id = ? AND users.role = 'user'",
        (session_id,),
    ).fetchone()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    db.execute("UPDATE sessions SET revoked_at = ? WHERE id = ?", (iso_now(), session_id))
    log_admin(db, admin["admin_id"], "revoke_session", session["email"])
    db.commit()
    return JSONResponse({"status": "revoked"})


@app.post("/admin/users/{user_id}/sessions/revoke")
def admin_revoke_user_sessions(user_id: int, admin: Annotated[dict, Depends(require_admin)], db: Connection = Depends(get_db)) -> JSONResponse:
    target = db.execute("SELECT * FROM users WHERE id = ? AND role = 'user'", (user_id,)).fetchone()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    revoke_user_sessions(db, user_id)
    log_admin(db, admin["admin_id"], "revoke_user_sessions", target["email"])
    db.commit()
    return JSONResponse({"status": "revoked", "email": target["email"]})


@app.post("/admin/sessions/revoke-all")
def admin_revoke_all_sessions(admin: Annotated[dict, Depends(require_admin)], db: Connection = Depends(get_db)) -> JSONResponse:
    revoke_all_sessions(db)
    log_admin(db, admin["admin_id"], "revoke_all_sessions")
    db.commit()
    return JSONResponse({"status": "revoked_all"})


@app.get("/admin/audit-logs")
def admin_audit_logs(admin: Annotated[dict, Depends(require_admin)], db: Connection = Depends(get_db)) -> JSONResponse:
    logs = db.execute(
        """
        SELECT audit_logs.*, admins.email AS controller_email
        FROM audit_logs LEFT JOIN admins ON admins.id = audit_logs.admin_id
        ORDER BY audit_logs.timestamp DESC
        """
    ).fetchall()
    log_admin(db, admin["admin_id"], "view_audit_logs")
    db.commit()
    return JSONResponse({"audit_logs": logs})


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}
