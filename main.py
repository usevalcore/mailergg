from fastapi import FastAPI, Request
from app.database import get_db, save_email
from datetime import datetime

app = FastAPI(title="Mailergg Email Webhook API")

# Simple ping route to test server
@app.get("/ping")
async def ping():
    return {"status": "running"}

# Email webhook endpoint
@app.post("/webhook/email")
async def email_webhook(req: Request):
    try:
        data = await req.json()
    except Exception:
        return {"error": "Invalid JSON"}

    print("🔥 EMAIL RECEIVED:", data)

    # Validate required fields
    for field in ["from", "to", "subject", "body"]:
        if field not in data:
            return {"error": f"Missing field: {field}"}

    # Save email to the database
    db = next(get_db())
    save_email(
        db=db,
        sender=data["from"],
        recipient=data["to"],
        subject=data["subject"],
        body=data["body"],
        received_at=datetime.utcnow().isoformat()
    )

    return {"ok": True}

# Optional root route
@app.get("/")
async def root():
    return {"status": "Mailergg FastAPI running"}
