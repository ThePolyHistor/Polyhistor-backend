from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlmodel import Session, select

from core.database import get_session
from core.config import settings
from models.user import User, TokenBlocklist
from schemas.auth import TokenData

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

def get_current_user(token: str = Depends(oauth2_scheme), session: Session = Depends(get_session)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        email: str = payload.get("sub")
        jti: str = payload.get("jti")

        if email is None or jti is None:
            raise credentials_exception
        
        # Check if the token has been blocklisted (logged out)
        blocklisted_token = session.exec(select(TokenBlocklist).where(TokenBlocklist.jti == jti)).first()
        if blocklisted_token:
            raise credentials_exception

        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception
    
    user = session.exec(select(User).where(User.email == token_data.email)).first()
    if user is None or not user.is_active:
        raise credentials_exception
        
    return user