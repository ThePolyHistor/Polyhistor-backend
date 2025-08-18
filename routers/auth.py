from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import Session, select
from datetime import datetime, timedelta # No longer need timezone
from jose import JWTError, jwt

from auth import security
from auth.dependencies import get_current_user, oauth2_scheme
from core.database import get_session
from core.config import settings
from core.mailer import send_verification_email, send_password_reset_email
from models.user import User, TokenBlocklist
from schemas.user import UserCreate, UserPublic
from schemas.auth import (
    Token, EmailSchema, PasswordResetSchema, VerificationCodeSchema,
    MessageResponse, TokenResponse, UserResponse
)

router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.post("/signup", response_model=MessageResponse, status_code=status.HTTP_201_CREATED)
def create_user(
    user: UserCreate,
    background_tasks: BackgroundTasks,
    session: Session = Depends(get_session)
):
    db_user_by_email = session.exec(select(User).where(User.email == user.email)).first()
    if db_user_by_email:
        raise HTTPException(status_code=400, detail="Email already registered")

    db_user_by_username = session.exec(select(User).where(User.username == user.username)).first()
    if db_user_by_username:
        raise HTTPException(status_code=400, detail="Username already taken")

    hashed_password = security.get_password_hash(user.password)
    user_data = user.model_dump(exclude_unset=True)
    user_data["hashed_password"] = hashed_password
    
    new_user = User(**user_data)
    
    verification_code = security.generate_verification_code()
    new_user.verification_code = verification_code
    # Use datetime.utcnow() to get a naive UTC datetime
    new_user.verification_code_expires_at = datetime.utcnow() + timedelta(minutes=10)

    session.add(new_user)
    session.commit()
    session.refresh(new_user)

    background_tasks.add_task(send_verification_email, new_user.email, verification_code)

    return MessageResponse(message="Signup successful. Please check your email for the verification code.")


@router.post("/verify-code", response_model=MessageResponse)
def verify_code(
    verification_data: VerificationCodeSchema,
    session: Session = Depends(get_session)
):
    user = session.exec(select(User).where(User.email == verification_data.email)).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    
    if user.is_active:
        raise HTTPException(status_code=400, detail="Account is already active.")

    if user.verification_code != verification_data.code:
        raise HTTPException(status_code=400, detail="Invalid verification code.")
    
    # Check for expiration before comparing datetimes
    if not user.verification_code_expires_at:
        raise HTTPException(status_code=400, detail="Verification code has no expiration.")
        
    # Use datetime.utcnow() here as well for a consistent comparison
    if user.verification_code_expires_at < datetime.utcnow():
        raise HTTPException(status_code=400, detail="Verification code has expired.")
        
    user.is_active = True
    user.verification_code = None 
    user.verification_code_expires_at = None
    
    session.add(user)
    session.commit()
    
    return MessageResponse(message="Account verified successfully.")


@router.post("/login", response_model=TokenResponse)
def login(form_data: OAuth2PasswordRequestForm = Depends(), session: Session = Depends(get_session)):
    user = session.exec(select(User).where(User.email == form_data.username)).first()
    if not user or not security.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403, 
            detail="Account not active. Please verify your email."
        )

    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = security.create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    refresh_token = security.create_refresh_token(data={"sub": user.email})

    token_data = Token(access_token=access_token, refresh_token=refresh_token)
    return TokenResponse(
        message="Login successful",
        data=token_data
    )


@router.post("/forgot-password", response_model=MessageResponse)
def forgot_password(
    email_schema: EmailSchema,
    background_tasks: BackgroundTasks,
    session: Session = Depends(get_session)
):
    user = session.exec(select(User).where(User.email == email_schema.email)).first()
    if user:
        token = security.create_access_token(
            data={"sub": user.email},
            expires_delta=timedelta(minutes=15)
        )
        background_tasks.add_task(send_password_reset_email, user.email, token)
        
    return MessageResponse(message="If an account with that email exists, a password reset link has been sent.")


@router.post("/reset-password", response_model=MessageResponse)
def reset_password(
    reset_schema: PasswordResetSchema,
    session: Session = Depends(get_session)
):
    try:
        payload = jwt.decode(reset_schema.token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=400, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid token")
        
    user = session.exec(select(User).where(User.email == email)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    user.hashed_password = security.get_password_hash(reset_schema.new_password)
    session.add(user)
    session.commit()
    
    return MessageResponse(message="Password has been reset successfully.")


@router.post("/refresh", response_model=TokenResponse)
def refresh_token(refresh_token: str, session: Session = Depends(get_session)):
    try:
        payload = jwt.decode(refresh_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid refresh token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
        
    user = session.exec(select(User).where(User.email == email)).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")
        
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    new_access_token = security.create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    new_refresh_token = security.create_refresh_token(data={"sub": user.email})
    
    token_data = Token(access_token=new_access_token, refresh_token=new_refresh_token)
    return TokenResponse(
        message="Tokens refreshed successfully",
        data=token_data
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(token: str = Depends(oauth2_scheme), session: Session = Depends(get_session)):
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        jti = payload.get("jti")
        if not jti:
            raise HTTPException(status_code=400, detail="Invalid token")

        blocklisted_token = TokenBlocklist(jti=jti)
        session.add(blocklisted_token)
        session.commit()
    except JWTError:
        raise HTTPException(status_code=401, detail="Could not validate credentials")

@router.post("/resend-verification-code", response_model=MessageResponse)
def resend_verification_code(
    email_schema: EmailSchema,
    background_tasks: BackgroundTasks,
    session: Session = Depends(get_session)
):
    """
    Resends a verification code to a user's email if they are not yet active.
    """
    user = session.exec(select(User).where(User.email == email_schema.email)).first()

    if not user:
        return MessageResponse(message="If an account with that email exists and is not verified, a new code has been sent.")

    if user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="This account is already active.")

    verification_code = security.generate_verification_code()
    user.verification_code = verification_code
    user.verification_code_expires_at = datetime.utcnow() + timedelta(minutes=10)

    session.add(user)
    session.commit()

    background_tasks.add_task(send_verification_email, user.email, verification_code)

    return MessageResponse(message="A new verification code has been sent to your email.")

@router.get("/users/me", response_model=UserResponse)
def read_users_me(current_user: User = Depends(get_current_user)):
    return UserResponse(
        message="User data retrieved successfully",
        data=current_user
    )
