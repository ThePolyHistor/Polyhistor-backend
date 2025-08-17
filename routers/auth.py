from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import Session, select
from datetime import timedelta
from jose import JWTError, jwt

from auth import security
from auth.dependencies import get_current_user, oauth2_scheme
from core.database import get_session
from core.config import settings
from core.mailer import send_verification_email, send_password_reset_email
from models.user import User, TokenBlocklist
from schemas.user import UserCreate, UserPublic
from schemas.auth import Token, EmailSchema, PasswordResetSchema

router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.post("/signup", status_code=status.HTTP_201_CREATED)
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
    session.add(new_user)
    session.commit()
    session.refresh(new_user)

    # Generate a token and send verification email in the background
    token = security.create_access_token(
        data={"sub": new_user.email},
        expires_delta=timedelta(minutes=15)
    )
    background_tasks.add_task(send_verification_email, new_user.email, token)

    return {"message": "Signup successful. Please check your email to verify your account."}


@router.get("/verify-email")
def verify_email(token: str, session: Session = Depends(get_session)):
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=400, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid token")

    user = session.exec(select(User).where(User.email == email)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.is_active:
        return {"message": "Email already verified"}
        
    user.is_active = True
    session.add(user)
    session.commit()
    
    return {"message": "Email verified successfully"}


@router.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), session: Session = Depends(get_session)):
    user = session.exec(select(User).where(User.email == form_data.username)).first()
    if not user or not security.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(
            status_code=403, 
            detail="Account not active. Please verify your email."
        )

    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = security.create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    refresh_token = security.create_refresh_token(data={"sub": user.email})

    return Token(access_token=access_token, refresh_token=refresh_token)


@router.post("/forgot-password")
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
        
    return {"message": "If an account with that email exists, a password reset link has been sent."}


@router.post("/reset-password")
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
    
    return {"message": "Password has been reset successfully."}


@router.post("/refresh", response_model=Token)
def refresh_token(refresh_token: str, session: Session = Depends(get_session)):
    try:
        payload = jwt.decode(refresh_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid refresh token")
        
        user = session.exec(select(User).where(User.email == email)).first()
        if not user or not user.is_active:
            raise HTTPException(status_code=401, detail="User not found or inactive")
        
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        new_access_token = security.create_access_token(
            data={"sub": user.email}, expires_delta=access_token_expires
        )
        new_refresh_token = security.create_refresh_token(data={"sub": user.email})
        
        return Token(access_token=new_access_token, refresh_token=new_refresh_token)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")


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


@router.get("/users/me", response_model=UserPublic)
def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user