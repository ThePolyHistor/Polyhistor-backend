from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from core.database import create_db_and_tables
from routers import auth as auth_router

app = FastAPI(
    title="PolyHistor Apis",
    description="Backend for the Polyhistor.",
    version="1.0.0"
)

# CORS Middleware: Update origins to your React Native app's domain in production
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # For development. Be more restrictive in production.
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def on_startup():
    create_db_and_tables()

app.include_router(auth_router.router)

@app.get("/")
def read_root():
    return {"message": "Welcome to the API"}