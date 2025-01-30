# app/main.py
from fastapi import FastAPI
from app.auth import router as auth_router
from app.fhir import router as fhir_router

app = FastAPI()
app.include_router(auth_router)
app.include_router(fhir_router)
