import uuid
from datetime import datetime
from sqlmodel import Field, SQLModel
from typing import Optional

class User(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    username: str = Field(unique=True, index=True)
    first_name: Optional[str] = Field(default=None)
    last_name: Optional[str] = Field(default=None)
    mobile_number: Optional[str] = Field(default=None, unique=True)
    email: str = Field(unique=True, index=True)
    hashed_password: str
    is_active: bool = Field(default=False)
    created_at: datetime = Field(default_factory=datetime.utcnow)

class TokenBlocklist(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    jti: str = Field(index=True) # jti is the unique identifier for a token
    created_at: datetime = Field(default_factory=datetime.utcnow)