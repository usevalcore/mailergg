from fastapi import FastAPI, Request
from app.database import get_db, save_email

app = FastAPI()


@app.post("/webhook/email")
async def email_webhook(req: Request):
    data = await req.json()

    print("🔥 EMAIL RECEIVED:", data)

    db = next(get_db())

    save_email(
        db=db,
        sender=data["from"],
        recipient=data["to"],
        subject=data["subject"],
        body=data["body"]
    )

    return {"ok": True}
