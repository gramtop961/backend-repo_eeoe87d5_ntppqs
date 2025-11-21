"""
Database Schemas for Slash Messenger

Each Pydantic model represents a MongoDB collection (collection name is the lowercase class name).
"""
from typing import Optional, Literal
from pydantic import BaseModel, Field

class User(BaseModel):
    name: str = Field(..., description="Full name")
    username: str = Field(..., description="Unique username (lowercase, no spaces)")
    number: str = Field(..., description="Phone number as string")
    password_hash: str = Field(..., description="Hashed password")
    avatar_url: Optional[str] = Field(None, description="Public profile picture URL")
    bio: Optional[str] = Field(None, description="Short bio/status")
    is_active: bool = Field(True, description="Account active (not suspended)")
    is_admin: bool = Field(False, description="Admin role flag")

class Session(BaseModel):
    user_id: str
    token: str
    role: Literal["user", "admin"] = "user"
    ip: Optional[str] = None
    valid: bool = True

class Message(BaseModel):
    sender_id: str
    receiver_id: str
    kind: Literal["text","image","video","audio","voice"] = "text"
    text: Optional[str] = None
    media_url: Optional[str] = None
    read: bool = False

class Block(BaseModel):
    blocker_id: str
    blocked_id: str

class Adminlog(BaseModel):
    action: str
    actor_id: Optional[str] = None
    target_id: Optional[str] = None
    details: Optional[str] = None
