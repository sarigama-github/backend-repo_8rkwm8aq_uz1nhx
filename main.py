import os
import secrets
import string
import base64
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from database import db, create_document, get_documents

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def read_root():
    return {"message": "Hello from FastAPI Backend!"}


@app.get("/api/hello")
def hello():
    return {"message": "Hello from the backend API!"}


@app.get("/test")
def test_database():
    """Test endpoint to check if database is available and accessible"""
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }

    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = db.name if hasattr(db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    # Check environment variables
    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"

    return response


# ----------------------
# Helpers
# ----------------------
SESSION_TTL_MINUTES = 10
WEBAUTHN_TTL_MINUTES = 10

def _random_token(n: int = 32) -> str:
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(n))

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')

def _from_b64url(data: str) -> bytes:
    padding = '=' * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


# ----------------------
# QR Login Implementation
# ----------------------

class StartQRResponse(BaseModel):
    token: str
    approve_url: str
    expires_at: str


class ApproveRequest(BaseModel):
    token: str


@app.post("/qr/start", response_model=StartQRResponse)
def start_qr_login():
    """
    Create a one-time QR login session. Returns a token and an approval URL
    that can be encoded into a QR code.
    """
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")

    token = _random_token(40)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=SESSION_TTL_MINUTES)

    session_doc = {
        "token": token,
        "status": "pending",  # pending -> approved -> consumed/expired
        "created_at": now,
        "updated_at": now,
        "expires_at": expires_at,
    }
    db["authsession"].insert_one(session_doc)

    # The approve URL is a frontend route that the mobile device will open
    frontend_base = os.getenv("FRONTEND_URL") or os.getenv("VITE_FRONTEND_URL") or ""
    # The client can still construct its own approve link if this is empty
    approve_url = f"/qr/approve?token={token}"
    if frontend_base:
        approve_url = f"{frontend_base.rstrip('/')}{approve_url}"

    return StartQRResponse(
        token=token,
        approve_url=approve_url,
        expires_at=expires_at.isoformat(),
    )


@app.get("/qr/status/{token}")
def qr_status(token: str):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")

    doc = db["authsession"].find_one({"token": token})
    if not doc:
        raise HTTPException(status_code=404, detail="Session not found")

    now = datetime.now(timezone.utc)
    expired = now > doc.get("expires_at", now)
    status = doc.get("status", "pending")

    if expired and status != "consumed":
        db["authsession"].update_one({"_id": doc["_id"]}, {"$set": {"status": "expired", "updated_at": now}})
        status = "expired"

    return {
        "status": status,
        "expires_at": doc.get("expires_at").isoformat() if doc.get("expires_at") else None
    }


@app.post("/qr/approve")
def qr_approve(payload: ApproveRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")

    doc = db["authsession"].find_one({"token": payload.token})
    if not doc:
        raise HTTPException(status_code=404, detail="Session not found")

    now = datetime.now(timezone.utc)
    if now > doc.get("expires_at", now):
        db["authsession"].update_one({"_id": doc["_id"]}, {"$set": {"status": "expired", "updated_at": now}})
        raise HTTPException(status_code=400, detail="Session expired")

    if doc.get("status") in ("approved", "consumed"):
        return {"ok": True, "status": doc.get("status")}

    db["authsession"].update_one(
        {"_id": doc["_id"]},
        {"$set": {"status": "approved", "approved_at": now, "updated_at": now}},
    )
    return {"ok": True, "status": "approved"}


@app.post("/qr/consume/{token}")
def qr_consume(token: str):
    """Mark an approved session as consumed (used for finalizing login)."""
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")

    doc = db["authsession"].find_one({"token": token})
    if not doc:
        raise HTTPException(status_code=404, detail="Session not found")

    if doc.get("status") != "approved":
        raise HTTPException(status_code=400, detail="Session not approved yet")

    now = datetime.now(timezone.utc)
    db["authsession"].update_one({"_id": doc["_id"]}, {"$set": {"status": "consumed", "updated_at": now}})
    return {"ok": True}


# ----------------------
# Minimal WebAuthn Demo Endpoints (non-cryptographic demo)
# ----------------------

class StartRegRequest(BaseModel):
    email: str
    name: Optional[str] = None

class StartRegResponse(BaseModel):
    challenge: str
    rpId: str
    userId: str

class FinishRegRequest(BaseModel):
    email: str
    name: Optional[str] = None
    id: str
    rawId: str
    response: Dict[str, Any]
    type: str

class StartLoginRequest(BaseModel):
    email: str

class StartLoginResponse(BaseModel):
    challenge: str
    rpId: str
    allowCredentials: Optional[list] = None

class FinishLoginRequest(BaseModel):
    email: str
    id: str
    rawId: str
    response: Dict[str, Any]
    type: str


def _issue_challenge(email: str, kind: str = "registration") -> dict:
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    challenge = os.urandom(32)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=WEBAUTHN_TTL_MINUTES)
    doc = {
        "email": email,
        "kind": kind,
        "challenge": _b64url(challenge),
        "created_at": now,
        "updated_at": now,
        "expires_at": expires_at,
        "used": False,
    }
    db["authchallenge"].insert_one(doc)
    return doc


def _get_rp_id(request: Request) -> str:
    host = request.headers.get("host", "localhost")
    # strip port
    return host.split(":")[0]


@app.post("/webauthn/register/start", response_model=StartRegResponse)
async def webauthn_register_start(req: Request, payload: StartRegRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    ch = _issue_challenge(payload.email, "registration")
    rp_id = _get_rp_id(req)
    user_id = _b64url(payload.email.encode("utf-8"))
    return StartRegResponse(challenge=ch["challenge"], rpId=rp_id, userId=user_id)


@app.post("/webauthn/register/finish")
async def webauthn_register_finish(payload: FinishRegRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    # Lookup latest registration challenge
    ch = db["authchallenge"].find_one({"email": payload.email, "kind": "registration", "used": False}, sort=[("created_at", -1)])
    if not ch:
        raise HTTPException(status_code=400, detail="No active challenge")
    now = datetime.now(timezone.utc)
    if now > ch.get("expires_at", now):
        raise HTTPException(status_code=400, detail="Challenge expired")

    # Upsert user and store credential id (no full verification in demo)
    users = db["authuser"]
    user = users.find_one({"email": payload.email})
    cred = {
        "cred_id": payload.id,
        "created_at": now,
        "sign_count": 0,
    }
    if user:
        users.update_one({"_id": user["_id"]}, {"$set": {"name": payload.name or user.get("name")}, "$addToSet": {"credentials": cred}})
    else:
        users.insert_one({
            "email": payload.email,
            "name": payload.name,
            "credentials": [cred],
            "is_active": True,
            "created_at": now,
            "updated_at": now,
        })

    db["authchallenge"].update_one({"_id": ch["_id"]}, {"$set": {"used": True, "updated_at": now}})
    return {"ok": True}


@app.post("/webauthn/login/start", response_model=StartLoginResponse)
async def webauthn_login_start(req: Request, payload: StartLoginRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    user = db["authuser"].find_one({"email": payload.email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    ch = _issue_challenge(payload.email, "login")
    rp_id = _get_rp_id(req)
    allow = [{"type": "public-key", "id": c.get("cred_id")} for c in user.get("credentials", [])]
    return StartLoginResponse(challenge=ch["challenge"], rpId=rp_id, allowCredentials=allow)


@app.post("/webauthn/login/finish")
async def webauthn_login_finish(payload: FinishLoginRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    ch = db["authchallenge"].find_one({"email": payload.email, "kind": "login", "used": False}, sort=[("created_at", -1)])
    if not ch:
        raise HTTPException(status_code=400, detail="No active challenge")
    now = datetime.now(timezone.utc)
    if now > ch.get("expires_at", now):
        raise HTTPException(status_code=400, detail="Challenge expired")

    # Check that credential id is known
    user = db["authuser"].find_one({"email": payload.email, "credentials.cred_id": payload.id})
    if not user:
        raise HTTPException(status_code=400, detail="Unknown credential")

    # Mark used
    db["authchallenge"].update_one({"_id": ch["_id"]}, {"$set": {"used": True, "updated_at": now}})
    # Issue a simple session token (demo)
    session_token = _random_token(32)
    db["authsession"].insert_one({
        "token": session_token,
        "status": "consumed",
        "kind": "login",
        "email": payload.email,
        "created_at": now,
        "updated_at": now,
        "expires_at": now + timedelta(hours=12),
    })
    return {"ok": True, "session": session_token}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
