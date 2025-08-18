from sqlmodel import SQLModel
from .common import StandardResponse
from .user import UserPublic

class Token(SQLModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class TokenData(SQLModel):
    email: str | None = None

class EmailSchema(SQLModel):
    email: str

class PasswordResetSchema(SQLModel):
    token: str
    new_password: str

class VerificationCodeSchema(SQLModel):
    email: str
    code: str

class MessageResponse(StandardResponse):
    """A standard response for simple messages."""
    pass

class TokenResponse(StandardResponse[Token]):
    """The response for a successful login or token refresh."""
    pass

class UserResponse(StandardResponse[UserPublic]):
    """The response for returning a single user's public data."""
    pass
