import os
from uuid import uuid4
from datetime import datetime, timezone
from typing import Optional, List, Literal, Dict, Any

from fastapi import FastAPI, HTTPException, Depends, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from bson import ObjectId

from database import db, create_document, get_documents
from schemas import User as UserSchema, Message as MessageSchema, Block as BlockSchema, Session as SessionSchema, Adminlog as AdminlogSchema

import hashlib

app = FastAPI(title="Slash Messenger API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer(auto_error=False)

ADMIN_USERNAME = "online911"
ADMIN_PASSWORD = "onlinE@911"


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def oid(id_str: str) -> ObjectId:
    try:
        return ObjectId(id_str)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid ID")


class SignupPayload(BaseModel):
    name: str
    username: str
    number: str
    password: str


class LoginPayload(BaseModel):
    identifier: str  # username or number
    password: str


class UpdateProfilePayload(BaseModel):
    name: Optional[str] = None
    username: Optional[str] = None
    number: Optional[str] = None
    password: Optional[str] = None
    avatar_url: Optional[str] = None
    bio: Optional[str] = None


class SendMessagePayload(BaseModel):
    to_identifier: str  # username or user_id
    kind: Literal["text","image","video","audio","voice"] = "text"
    text: Optional[str] = None
    media_url: Optional[str] = None


class AdminEditUserPayload(BaseModel):
    name: Optional[str] = None
    username: Optional[str] = None
    number: Optional[str] = None
    password: Optional[str] = None
    avatar_url: Optional[str] = None
    bio: Optional[str] = None
    is_active: Optional[bool] = None


def public_user(u: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": str(u.get("_id")),
        "name": u.get("name"),
        "username": u.get("username"),
        "number": u.get("number"),
        "avatar_url": u.get("avatar_url"),
        "bio": u.get("bio"),
        "is_active": u.get("is_active", True),
    }


async def get_current_session(request: Request, creds: Optional[HTTPAuthorizationCredentials] = Depends(security)):
    if creds is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = creds.credentials
    sess = db["session"].find_one({"token": token, "valid": True})
    if not sess:
        raise HTTPException(status_code=401, detail="Invalid session")
    user = db["user"].find_one({"_id": sess["user_id"]})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    if not user.get("is_active", True):
        # invalidate this session
        db["session"].update_many({"user_id": user["_id"]}, {"$set": {"valid": False}})
        raise HTTPException(status_code=403, detail="Account is suspended")
    return {"session": sess, "user": user}


@app.get("/")
def read_root():
    return {"message": "Slash Messenger API running"}


@app.get("/test")
def test_database():
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
            response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
            response["database_name"] = db.name if hasattr(db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️ Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️ Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"
    return response


@app.post("/auth/signup")
def signup(payload: SignupPayload, request: Request):
    if db["user"].find_one({"$or": [{"username": payload.username.lower()}, {"number": payload.number}]}):
        raise HTTPException(status_code=400, detail="Username or number already exists")
    is_admin = payload.username == ADMIN_USERNAME and payload.password == ADMIN_PASSWORD
    user_data = UserSchema(
        name=payload.name,
        username=payload.username.lower(),
        number=payload.number,
        password_hash=hash_password(payload.password),
        avatar_url=None,
        bio=None,
        is_active=True,
        is_admin=is_admin,
    )
    user_id = create_document("user", user_data)
    user_doc = db["user"].find_one({"_id": ObjectId(user_id)})

    # auto login
    token = str(uuid4())
    sess = SessionSchema(user_id=user_doc["_id"], token=token, role="admin" if is_admin else "user", ip=request.client.host, valid=True)
    create_document("session", sess)
    return {"token": token, "user": public_user(user_doc), "role": sess.role}


@app.post("/auth/login")
def login(payload: LoginPayload, request: Request):
    identifier = payload.identifier.lower()
    user = db["user"].find_one({"$or": [{"username": identifier}, {"number": identifier}]})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if user.get("password_hash") != hash_password(payload.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.get("is_active", True):
        raise HTTPException(status_code=403, detail="Account is suspended")

    token = str(uuid4())
    role = "admin" if user.get("is_admin") else "user"
    sess = SessionSchema(user_id=user["_id"], token=token, role=role, ip=request.client.host, valid=True)
    create_document("session", sess)
    return {"token": token, "user": public_user(user), "role": role}


@app.post("/auth/logout")
def logout(ctx=Depends(get_current_session)):
    db["session"].update_one({"_id": ctx["session"]["_id"]}, {"$set": {"valid": False}})
    return {"ok": True}


@app.get("/me")
def get_me(ctx=Depends(get_current_session)):
    return public_user(ctx["user"])


@app.patch("/me")
def update_me(payload: UpdateProfilePayload, ctx=Depends(get_current_session)):
    updates: Dict[str, Any] = {}
    if payload.name is not None:
        updates["name"] = payload.name
    if payload.username is not None:
        newu = payload.username.lower()
        exists = db["user"].find_one({"username": newu, "_id": {"$ne": ctx["user"]["_id"]}})
        if exists:
            raise HTTPException(status_code=400, detail="Username already taken")
        updates["username"] = newu
    if payload.number is not None:
        exists = db["user"].find_one({"number": payload.number, "_id": {"$ne": ctx["user"]["_id"]}})
        if exists:
            raise HTTPException(status_code=400, detail="Number already used")
        updates["number"] = payload.number
    if payload.password is not None:
        updates["password_hash"] = hash_password(payload.password)
    if payload.avatar_url is not None:
        updates["avatar_url"] = payload.avatar_url
    if payload.bio is not None:
        updates["bio"] = payload.bio
    if updates:
        updates["updated_at"] = datetime.now(timezone.utc)
        db["user"].update_one({"_id": ctx["user"]["_id"]}, {"$set": updates})
    user = db["user"].find_one({"_id": ctx["user"]["_id"]})
    return public_user(user)


@app.get("/users/search")
def search_users(q: str, ctx=Depends(get_current_session)):
    query = {"$or": [
        {"username": {"$regex": q.lower(), "$options": "i"}},
        {"number": {"$regex": q, "$options": "i"}},
        {"name": {"$regex": q, "$options": "i"}},
    ], "is_active": True}
    users = list(db["user"].find(query).limit(20))

    # Apply block visibility: if either party blocked, hide avatar
    blocked_any = db["block"].find_one({"$or": [
        {"blocker_id": ctx["user"]["_id"], "blocked_id": {"$in": [u["_id"] for u in users]}},
        {"blocked_id": ctx["user"]["_id"], "blocker_id": {"$in": [u["_id"] for u in users]}},
    ]})
    result = []
    for u in users:
        pu = public_user(u)
        # check per user block
        is_blocked = db["block"].find_one({"$or": [
            {"blocker_id": ctx["user"]["_id"], "blocked_id": u["_id"]},
            {"blocker_id": u["_id"], "blocked_id": ctx["user"]["_id"]},
        ]}) is not None
        if is_blocked:
            pu["avatar_url"] = None
        result.append(pu)
    return result


def resolve_user(identifier: str) -> Optional[dict]:
    try:
        return db["user"].find_one({"_id": ObjectId(identifier)})
    except Exception:
        return db["user"].find_one({"username": identifier.lower()})


@app.post("/messages/send")
def send_message(payload: SendMessagePayload, ctx=Depends(get_current_session)):
    to_user = resolve_user(payload.to_identifier)
    if not to_user:
        raise HTTPException(status_code=404, detail="Recipient not found")

    # block checks (both directions)
    if db["block"].find_one({"blocker_id": ctx["user"]["_id"], "blocked_id": to_user["_id"]}) or \
       db["block"].find_one({"blocker_id": to_user["_id"], "blocked_id": ctx["user"]["_id"]}):
        raise HTTPException(status_code=403, detail="Messaging is blocked")

    if payload.kind == "text" and not payload.text:
        raise HTTPException(status_code=400, detail="Text required for text messages")
    if payload.kind != "text" and not payload.media_url:
        raise HTTPException(status_code=400, detail="media_url required for non-text messages")

    msg = MessageSchema(
        sender_id=str(ctx["user"]["_id"]),
        receiver_id=str(to_user["_id"]),
        kind=payload.kind,
        text=payload.text,
        media_url=payload.media_url,
        read=False,
    )
    mid = create_document("message", msg)
    doc = db["message"].find_one({"_id": ObjectId(mid)})
    return {
        "id": mid,
        "sender_id": str(doc["sender_id"]) if isinstance(doc["sender_id"], ObjectId) else doc["sender_id"],
        "receiver_id": str(doc["receiver_id"]) if isinstance(doc["receiver_id"], ObjectId) else doc["receiver_id"],
        "kind": doc.get("kind"),
        "text": doc.get("text"),
        "media_url": doc.get("media_url"),
        "created_at": doc.get("created_at"),
    }


@app.get("/messages/with/{other_id}")
def get_chat(other_id: str, ctx=Depends(get_current_session)):
    other = resolve_user(other_id)
    if not other:
        raise HTTPException(status_code=404, detail="User not found")
    # if blocked either way, hide media urls and avatars, but still show existing text? We'll restrict entirely
    if db["block"].find_one({"blocker_id": ctx["user"]["_id"], "blocked_id": other["_id"]}) or \
       db["block"].find_one({"blocker_id": other["_id"], "blocked_id": ctx["user"]["_id"]}):
        raise HTTPException(status_code=403, detail="Conversation is blocked")

    msgs = list(db["message"].find({
        "$or": [
            {"sender_id": str(ctx["user"]["_id"]), "receiver_id": str(other["_id"])},
            {"sender_id": str(other["_id"]), "receiver_id": str(ctx["user"]["_id"])},
        ]
    }).sort("created_at", 1).limit(200))

    def fmt(m):
        return {
            "id": str(m["_id"]),
            "sender_id": m.get("sender_id"),
            "receiver_id": m.get("receiver_id"),
            "kind": m.get("kind"),
            "text": m.get("text"),
            "media_url": m.get("media_url"),
            "created_at": m.get("created_at"),
        }

    return {
        "other": public_user(other),
        "messages": [fmt(m) for m in msgs]
    }


@app.get("/messages/conversations")
def conversations(ctx=Depends(get_current_session)):
    uid = str(ctx["user"]["_id"])
    # naive last message per peer
    msgs = list(db["message"].find({"$or": [{"sender_id": uid}, {"receiver_id": uid}]}).sort("created_at", -1).limit(500))
    seen = {}
    convos = []
    for m in msgs:
        other_id = m["receiver_id"] if m["sender_id"] == uid else m["sender_id"]
        if other_id in seen:
            continue
        other = resolve_user(other_id)
        if not other:
            continue
        pu = public_user(other)
        # hide avatar if blocked either way
        is_blocked = db["block"].find_one({"$or": [
            {"blocker_id": ctx["user"]["_id"], "blocked_id": other["_id"]},
            {"blocker_id": other["_id"], "blocked_id": ctx["user"]["_id"]},
        ]}) is not None
        if is_blocked:
            pu["avatar_url"] = None
        convos.append({
            "other": pu,
            "last": {
                "id": str(m["_id"]),
                "kind": m.get("kind"),
                "text": m.get("text"),
                "media_url": m.get("media_url"),
                "created_at": m.get("created_at"),
            }
        })
        seen[other_id] = True
    return convos


@app.post("/block/{user_id}")
def block_user(user_id: str, ctx=Depends(get_current_session)):
    other = resolve_user(user_id)
    if not other:
        raise HTTPException(status_code=404, detail="User not found")
    if db["block"].find_one({"blocker_id": ctx["user"]["_id"], "blocked_id": other["_id"]}):
        return {"ok": True}
    blk = BlockSchema(blocker_id=str(ctx["user"]["_id"]), blocked_id=str(other["_id"]))
    create_document("block", blk)
    return {"ok": True}


@app.delete("/block/{user_id}")
def unblock_user(user_id: str, ctx=Depends(get_current_session)):
    other = resolve_user(user_id)
    if not other:
        raise HTTPException(status_code=404, detail="User not found")
    db["block"].delete_many({"blocker_id": str(ctx["user"]["_id"]), "blocked_id": str(other["_id"])})
    return {"ok": True}


# Admin endpoints

def require_admin(ctx=Depends(get_current_session)):
    if not ctx["user"].get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin only")
    return ctx


@app.get("/admin/users")
def admin_list_users(ctx=Depends(require_admin)):
    users = list(db["user"].find({}))
    # Fetch last session and last IP
    result = []
    for u in users:
        last_sess = db["session"].find({"user_id": u["_id"]}).sort("created_at", -1).limit(1)
        last_ip = None
        if last_sess and last_sess.count(True) > 0:
            try:
                last_ip = list(last_sess)[0].get("ip")
            except Exception:
                last_ip = None
        item = public_user(u)
        item["is_admin"] = u.get("is_admin", False)
        item["last_ip"] = last_ip
        result.append(item)
    return result


@app.post("/admin/suspend/{user_id}")
def admin_suspend(user_id: str, ctx=Depends(require_admin)):
    u = resolve_user(user_id)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    db["user"].update_one({"_id": u["_id"]}, {"$set": {"is_active": False}})
    db["session"].update_many({"user_id": u["_id"]}, {"$set": {"valid": False}})
    log = AdminlogSchema(action="suspend", actor_id=str(ctx["user"]["_id"]), target_id=str(u["_id"]), details="Account suspended")
    create_document("adminlog", log)
    return {"ok": True}


@app.post("/admin/activate/{user_id}")
def admin_activate(user_id: str, ctx=Depends(require_admin)):
    u = resolve_user(user_id)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    db["user"].update_one({"_id": u["_id"]}, {"$set": {"is_active": True}})
    log = AdminlogSchema(action="activate", actor_id=str(ctx["user"]["_id"]), target_id=str(u["_id"]), details="Account activated")
    create_document("adminlog", log)
    return {"ok": True}


@app.patch("/admin/users/{user_id}")
def admin_edit_user(user_id: str, payload: AdminEditUserPayload, ctx=Depends(require_admin)):
    u = resolve_user(user_id)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    updates: Dict[str, Any] = {}
    if payload.name is not None:
        updates["name"] = payload.name
    if payload.username is not None:
        newu = payload.username.lower()
        exists = db["user"].find_one({"username": newu, "_id": {"$ne": u["_id"]}})
        if exists:
            raise HTTPException(status_code=400, detail="Username already taken")
        updates["username"] = newu
    if payload.number is not None:
        exists = db["user"].find_one({"number": payload.number, "_id": {"$ne": u["_id"]}})
        if exists:
            raise HTTPException(status_code=400, detail="Number already used")
        updates["number"] = payload.number
    if payload.password is not None:
        updates["password_hash"] = hash_password(payload.password)
    if payload.avatar_url is not None:
        updates["avatar_url"] = payload.avatar_url
    if payload.bio is not None:
        updates["bio"] = payload.bio
    if payload.is_active is not None:
        updates["is_active"] = payload.is_active
    if updates:
        updates["updated_at"] = datetime.now(timezone.utc)
        db["user"].update_one({"_id": u["_id"]}, {"$set": updates})
        log = AdminlogSchema(action="edit_user", actor_id=str(ctx["user"]["_id"]), target_id=str(u["_id"]), details=str(list(updates.keys())))
        create_document("adminlog", log)
    nu = db["user"].find_one({"_id": u["_id"]})
    return public_user(nu)


@app.get("/admin/logs")
def admin_logs(ctx=Depends(require_admin)):
    logs = list(db["adminlog"].find({}).sort("created_at", -1).limit(200))
    def fmt(l):
        return {
            "id": str(l["_id"]),
            "action": l.get("action"),
            "actor_id": l.get("actor_id"),
            "target_id": l.get("target_id"),
            "details": l.get("details"),
            "created_at": l.get("created_at"),
        }
    return [fmt(l) for l in logs]


# PDF backup
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
except Exception:
    letter = None
    canvas = None


@app.get("/admin/backup.pdf")
def admin_backup_pdf(response: Response, ctx=Depends(require_admin)):
    if canvas is None:
        raise HTTPException(status_code=500, detail="PDF library not available")
    import io
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter

    y = height - 40
    c.setFont("Helvetica-Bold", 16)
    c.drawString(40, y, "Slash Messenger Users Backup")
    y -= 24
    c.setFont("Helvetica", 10)
    c.drawString(40, y, f"Generated: {datetime.now(timezone.utc).isoformat()}")
    y -= 20

    users = list(db["user"].find({}).sort("created_at", 1))
    for u in users:
        if y < 80:
            c.showPage()
            y = height - 40
        c.setFont("Helvetica-Bold", 12)
        c.drawString(40, y, f"{u.get('name')} (@{u.get('username')})")
        y -= 16
        c.setFont("Helvetica", 10)
        c.drawString(60, y, f"Number: {u.get('number')} | Active: {u.get('is_active', True)} | Admin: {u.get('is_admin', False)}")
        y -= 14
        c.drawString(60, y, f"Avatar: {u.get('avatar_url') or '-'} | Bio: {u.get('bio') or '-'}")
        y -= 18

    c.showPage()
    c.save()
    pdf = buffer.getvalue()
    buffer.close()

    response.headers["Content-Disposition"] = "attachment; filename=slash_users_backup.pdf"
    return Response(content=pdf, media_type="application/pdf")


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
