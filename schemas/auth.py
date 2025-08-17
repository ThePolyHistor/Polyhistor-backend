from sqlmodel import SQLModel

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
