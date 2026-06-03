from fastapi import FastAPI, Request
from app.database import save_email  # adjust path if needed

app = FastAPI()

@app.post("/api/email/webhook")
async def email_webhook(req: Request):
    data = await req.json()
    save_email(
        sender=data["from"],
        recipient=data["to"],
        subject=data["subject"],
        body=data["body"]
    )
    return {"ok": True}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
