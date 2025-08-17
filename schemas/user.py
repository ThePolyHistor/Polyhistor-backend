import uuid
from sqlmodel import SQLModel
from typing import Optional

# Shared properties
class UserBase(SQLModel):
    email: str
    username: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    mobile_number: Optional[str] = None

# Properties to receive via API on creation
class UserCreate(UserBase):
    password: str

# Properties to return to client
class UserPublic(UserBase):
    id: uuid.UUID