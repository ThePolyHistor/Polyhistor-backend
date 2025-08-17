from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    # Database configuration
    DATABASE_URL: str

    # JWT settings
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    model_config = SettingsConfigDict(env_file=".env")

    # Email settings
    MAIL_USERNAME: str
    MAIL_PASSWORD: str
    MAIL_FROM: str
    MAIL_PORT: int
    MAIL_SERVER: str
    MAIL_STARTTLS: bool = True
    MAIL_SSL_TLS: bool = False
    
    FRONTEND_URL: str = "http://localhost:3000" 

    model_config = SettingsConfigDict(env_file=".env")

settings = Settings()