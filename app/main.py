# app/main.py
from fastapi import FastAPI
from app.auth import router as auth_router

app = FastAPI()
app.include_router(auth_router)
