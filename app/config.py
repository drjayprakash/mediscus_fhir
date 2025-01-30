# app/config.py
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

KEYCLOAK_SERVER_URL = os.getenv("KEYCLOAK_SERVER_URL", "https://auth.mediscus.in")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "smart")
KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "smartfhirclient")
KEYCLOAK_CLIENT_SECRET = os.getenv("KEYCLOAK_CLIENT_SECRET")
KEYCLOAK_REDIRECT_URI = os.getenv("KEYCLOAK_REDIRECT_URI", "http://localhost:8000/callback")
FHIR_SERVER_BASE = os.getenv("FHIR_SERVER_BASE", "https://fhir.mediscus.in")

# app/auth.py
from fastapi import APIRouter, Depends, HTTPException
import requests
from app.config import KEYCLOAK_SERVER_URL, KEYCLOAK_REALM, KEYCLOAK_CLIENT_ID, KEYCLOAK_CLIENT_SECRET, KEYCLOAK_REDIRECT_URI

router = APIRouter()

def get_token_url():
    return f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"

def get_auth_url():
    return f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/auth?client_id={KEYCLOAK_CLIENT_ID}&response_type=code&redirect_uri={KEYCLOAK_REDIRECT_URI}&scope=openid"

@router.get("/login")
def login():
    return {"login_url": get_auth_url()}

@router.get("/callback")
def callback(code: str):
    token_url = get_token_url()
    data = {
        "grant_type": "authorization_code",
        "client_id": KEYCLOAK_CLIENT_ID,
        "client_secret": KEYCLOAK_CLIENT_SECRET,
        "code": code,
        "redirect_uri": KEYCLOAK_REDIRECT_URI
    }
    response = requests.post(token_url, data=data)
    if response.status_code != 200:
        raise HTTPException(status_code=400, detail="Failed to get token")
    return response.json()

# app/main.py
from fastapi import FastAPI
from app.auth import router as auth_router

app = FastAPI()
app.include_router(auth_router)
