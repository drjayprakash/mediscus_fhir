# app/auth.py
from fastapi import APIRouter, Depends, HTTPException
import requests
from app.config import KEYCLOAK_BASE, KEYCLOAK_REALM, KEYCLOAK_CLIENT_ID, KEYCLOAK_CLIENT_SECRET, KEYCLOAK_REDIRECT_URI

router = APIRouter()

def get_token_url():
    return f"{KEYCLOAK_BASE}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"

def get_auth_url():
    return f"{KEYCLOAK_BASE}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/auth?client_id={KEYCLOAK_CLIENT_ID}&response_type=code&redirect_uri={KEYCLOAK_REDIRECT_URI}&scope=openid"

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
