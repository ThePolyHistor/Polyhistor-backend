# FastAPI Backend for PolyHistor

This repository contains the backend API for the PolyHistor application, built with FastAPI and PostgreSQL. It provides a robust, secure, and scalable foundation for user authentication and management, designed to be consumed by a React Native mobile application.

## ✨ Features

- **Token-Based Authentication:** Secure user access using JWT (JSON Web Tokens) with access and refresh tokens.
- **User Account Management:** Full CRUD operations for users, including signup and login.
- **Password Hashing:** Uses bcrypt to securely hash and verify user passwords.
- **Email Verification:** New user accounts are inactive until the user verifies their email address, preventing spam and ensuring valid user data.
- **Secure Password Reset:** A complete, token-based flow for users to securely reset forgotten passwords via email.
- **Logout Mechanism:** A true logout feature that blocklists JWTs, preventing their reuse even before expiration.
- **Database Integration:** Uses SQLModel (built on Pydantic and SQLAlchemy) for modern, type-safe interaction with a PostgreSQL database.
- **Automatic API Documentation:** Interactive API documentation and testing interface provided by Swagger UI at `/docs`.

## 📂 Project Structure

The project follows a modular and scalable structure to keep the codebase organized and maintainable.

```
/PolyHistor-Backend
|-- /auth                # Authentication logic, dependencies, and security utils
|   |-- dependencies.py  # FastAPI dependencies for token validation
|   `-- security.py      # Password hashing and JWT creation logic
|-- /core                # Core application logic and configuration
|   |-- config.py        # Pydantic settings for environment variables
|   |-- database.py      # Database connection and session management
|   `-- mailer.py        # Email sending service configuration
|-- /models              # Database table models
|   `-- user.py          # User and TokenBlocklist table schemas
|-- /routers             # API endpoint definitions
|   `-- auth.py          # All authentication-related routes
|-- /schemas             # Pydantic schemas for data validation
|   |-- auth.py          # Schemas for tokens and email/password forms
|   `-- user.py          # Schemas for user data (create, public)
|
|-- main.py              # Main FastAPI application instance and startup logic
|-- .env                 # Environment variables (local configuration)
`-- requirements.txt      # Project dependencies
```

## 🚀 Getting Started

Follow these instructions to get the project running on your local machine for development and testing.

### Prerequisites

- Python 3.10+
- PostgreSQL: A running PostgreSQL server.
- Homebrew (on macOS for installing PostgreSQL).

### 1. Installation & Setup

Clone the repository (if applicable):

```sh
git clone <your-repo-url>
cd PolyHistor-Backend
```

Create and activate a virtual environment:

```sh
python3 -m venv venv
source venv/bin/activate
```

Install dependencies:

```sh
pip install -r requirements.txt
```

### 2. Database Configuration

You need to create a PostgreSQL user and database for the application.

Connect to PostgreSQL:

```sh
psql postgres
```

Run the following SQL commands (replace `'your_user'`, `'your_password'`, and `'your_dbname'` with your credentials):

```sql
CREATE USER your_user WITH PASSWORD 'your_password';
CREATE DATABASE your_dbname;
GRANT ALL PRIVILEGES ON DATABASE your_dbname TO your_user;
\q
```

### 3. Environment Configuration

The application uses a `.env` file to manage secrets and configuration.

Create a `.env` file in the root directory and populate it with your settings. A template is provided below.

#### .env file

```env
# Generate a strong secret key. You can use: openssl rand -hex 32
SECRET_KEY="YOUR_STRONG_32_BYTE_HEX_SECRET_KEY"

# Your PostgreSQL database connection URL
DATABASE_URL="postgresql://your_user:your_password@localhost/your_dbname"

ALGORITHM="HS256"
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7

# Frontend URL (for links in emails)
FRONTEND_URL="http://localhost:3000"

# -- EMAIL SETTINGS (Example for Gmail) --
# NOTE: For Gmail, you must enable 2FA and create an "App Password"
MAIL_USERNAME="your.email@gmail.com"
MAIL_PASSWORD="your-16-character-app-password"
MAIL_FROM="your.email@gmail.com"
MAIL_PORT=587
MAIL_SERVER="smtp.gmail.com"
MAIL_STARTTLS=true
MAIL_SSL_TLS=false
```

### 4. Running the Application

Once the setup is complete, you can run the application using Uvicorn:

```sh
uvicorn main:app --reload
```

The `--reload` flag enables hot-reloading for development. The API will be available at [http://127.0.0.1:8000](http://127.0.0.1:8000).

## ⚙️ API Usage

The best way to explore and test the API is through the interactive documentation.

- **Interactive Docs (Swagger):** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

### Authentication Flow

1. **POST `/auth/signup`:** Create a new user. The account will be inactive.
2. **Email Verification:** The user receives an email with a verification link. They must click this link (or manually use the token in the `/auth/verify-email` endpoint) to activate the account.
3. **POST `/auth/login`:** The user logs in with their email and password to receive an `access_token` and `refresh_token`.
4. **Accessing Protected Routes:** Include the `access_token` in the Authorization header as a Bearer token (e.g., `Authorization: Bearer <token>`) to access protected endpoints like `/users/me`.
5. **POST `/auth/logout`:** Invalidates the current `access_token` by adding its unique identifier (JTI) to a blocklist.

## 🛠️ Key Technologies Used

- **FastAPI:** The modern, high-performance web framework for building APIs.
- **PostgreSQL:** Robust and reliable relational database.
- **SQLModel:** For defining database models with Python type hints.
- **Pydantic:** For data validation and settings management.
- **Passlib & python-jose:** For password hashing and JWT management.
- **Uvicorn:** The lightning-fast ASGI server.
- **fastapi-mail:** For sending emails asynchronously.
