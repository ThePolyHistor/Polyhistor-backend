import logging
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from core.config import settings

log = logging.getLogger(__name__)

conf = ConnectionConfig(
    MAIL_USERNAME=settings.MAIL_USERNAME,
    MAIL_PASSWORD=settings.MAIL_PASSWORD,
    MAIL_FROM=settings.MAIL_FROM,
    MAIL_PORT=settings.MAIL_PORT,
    MAIL_SERVER=settings.MAIL_SERVER,
    MAIL_STARTTLS=settings.MAIL_STARTTLS,
    MAIL_SSL_TLS=settings.MAIL_SSL_TLS,
    USE_CREDENTIALS=True,
    VALIDATE_CERTS=False # For development
)

async def send_verification_email(email_to: str, code: str):
    message = MessageSchema(
        subject="Your Verification Code",
        recipients=[email_to],
        body=f"""
        <p>Thank you for registering. Use the code below to verify your account:</p>
        <h2 style="font-size: 24px; letter-spacing: 4px; text-align: center;">{code}</h2>
        <p>This code will expire in 10 minutes.</p>
        """,
        subtype="html"
    )
    fm = FastMail(conf)
    await fm.send_message(message)
    log.info(f"Verification email with code sent to: {email_to}")


async def send_password_reset_email(email_to: str, token: str):
    message = MessageSchema(
        subject="Password Reset Request",
        recipients=[email_to],
        body=f"""
        <p>You requested a password reset. Click the link below to reset your password:</p>
        <p><a href="{settings.FRONTEND_URL}/reset-password?token={token}">Reset Password</a></p>
        <p>This link will expire in 15 minutes. If you did not request this, please ignore this email.</p>
        """,
        subtype="html"
    )
    fm = FastMail(conf)
    await fm.send_message(message)
    log.info(f"Password reset email sent to: {email_to}")
