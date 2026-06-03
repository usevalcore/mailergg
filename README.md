# MAILERGG

MAILERGG is a self-hosted, receive-only inbox application built with FastAPI, SQLite, server-side sessions, and Docker Compose. It supports real inbound email webhooks, user mailboxes with Inbox/Trash, search, attachments, locked-account review screens, and a separated controller account for user management.

## Features

- FastAPI backend with SQLite storage
- Separate controller/admin identity model
- Server-side revocable sessions
- Argon2 password hashing
- Seeded controller and first mailbox user from environment variables
- Inbox and Trash folders
- Full-text email search with SQLite FTS5
- Attachment storage on the filesystem
- Webhook ingestion at `/webhook/email`
- Controller `/viewer` for user creation and inbox inspection
- Backend-only control API for user lifecycle, session revocation, and audit logs
- PWA manifest and service worker
- Docker Compose single-command deployment

## Security Model

- Mailbox users can only log in, read/search mail, move mail to Trash, empty Trash, change display name, and change password.
- Controller/admin is not a mailbox user and does not receive mail.
- Controller actions are logged in `audit_logs`.
- Password reset, lock, delete, and session revoke actions immediately revoke affected user sessions.
- Locked users see a local red security-review screen. This is branding only and does not claim action on external services.
- Secrets must be supplied through environment variables or an uncommitted `.env` file.

## Local Setup

Copy the example environment file:

```bash
cp .env.example .env
```

Edit `.env` and set strong values for:

```text
ADMIN_PASSWORD=
FIRST_USER_PASSWORD=
```

For the requested default deployment, keep:

```text
ADMIN_EMAIL=cookpo222@gmail.com
FIRST_USER_EMAIL=jackmiller2@mailergg.me
```

Do not commit `.env`.

Start the app:

```bash
docker compose up --build -d
```

Open:

```text
http://localhost:8000
```

## Controller Login

Use the configured `ADMIN_EMAIL` and `ADMIN_PASSWORD` from your environment. After login, the controller is redirected to `/viewer`.

From `/viewer`, the controller can:

- create mailbox users
- inspect a selected user’s Inbox or Trash
- reset user passwords
- lock/unlock users
- delete users with PIN `6383`
- empty user Trash

## First User

The first mailbox user is seeded from:

```text
FIRST_USER_EMAIL
FIRST_USER_PASSWORD
FIRST_USER_DISPLAY_NAME
```

Users see a unique 10-digit account key in Settings for support verification.

## Testing Webhook Ingestion

Basic JSON payload:

```bash
curl -X POST http://localhost:8000/webhook/email \
  -H "Content-Type: application/json" \
  -d '{
    "recipient_email": "jackmiller2@mailergg.me",
    "sender_email": "sender@example.com",
    "subject": "Hello",
    "body": "Delivered through the inbound webhook.",
    "timestamp": "2026-06-03T15:01:00Z"
  }'
```

JSON payload with base64 attachment:

```bash
curl -X POST http://localhost:8000/webhook/email \
  -H "Content-Type: application/json" \
  -d '{
    "recipient_email": "jackmiller2@mailergg.me",
    "sender_email": "sender@example.com",
    "subject": "Attachment test",
    "body": "File attached.",
    "timestamp": "2026-06-03T15:02:00Z",
    "attachments": [
      {
        "filename": "note.txt",
        "content_type": "text/plain",
        "content": "SGVsbG8gZnJvbSBNQUlMRVJHRy4="
      }
    ]
  }'
```

Multipart payload:

```bash
curl -X POST http://localhost:8000/webhook/email \
  -F "recipient_email=jackmiller2@mailergg.me" \
  -F "sender_email=sender@example.com" \
  -F "subject=Multipart attachment" \
  -F "body=File attached." \
  -F "timestamp=2026-06-03T15:03:00Z" \
  -F "attachment=@note.txt;type=text/plain"
```

Messages sent to the controller email are ignored because the controller is not a mailbox recipient.

## mailergg.me Email Routing

MAILERGG receives real mail when your email provider forwards inbound messages to:

```text
https://your-production-host.example.com/webhook/email
```

Accepted fields:

- `recipient_email`
- `sender_email`
- `subject`
- `body`
- `timestamp`
- optional `attachments`

Provider aliases also accepted:

- `to`
- `from`
- `recipient`
- `sender`
- `text`
- `html`
- `stripped-text`

### Cloudflare Email Routing

Cloudflare Email Routing requires a Worker bridge for webhook delivery:

1. Add `mailergg.me` to Cloudflare.
2. Enable Email Routing.
3. Configure Cloudflare’s MX records.
4. Create a Worker that receives routed mail.
5. Parse the inbound email in the Worker.
6. POST the normalized fields to `/webhook/email`.

Add provider signature verification or a private routing secret before exposing a production webhook publicly.

## Production Deployment

1. Provision a host with Docker and Docker Compose.
2. Clone the repository.
3. Copy `.env.example` to `.env`.
4. Set strong secrets in `.env`.
5. Put the app behind HTTPS.
6. Set:

```text
SESSION_COOKIE_SECURE=true
APP_BASE_URL=https://your-production-domain.example
```

7. Start:

```bash
docker compose up --build -d
```

8. Back up the Docker volume containing:

```text
/app/data/mailergg.sqlite
/app/data/attachments
```

## GitHub Safety

The repository is configured to ignore:

- `.env` files
- SQLite databases
- attachment data
- Docker/local runtime data
- cookies and verification artifacts
- Python caches

Never commit production credentials, tokens, databases, logs, or attachments.
