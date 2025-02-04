# app/auth.py
from fastapi import FastAPI, APIRouter, HTTPException
import requests
from app.config import KEYCLOAK_BASE, KEYCLOAK_REALM, KEYCLOAK_CLIENT_ID, KEYCLOAK_CLIENT_SECRET, KEYCLOAK_REDIRECT_URI

router = APIRouter()

from keycloak import KeycloakAdmin
from keycloak import KeycloakOpenIDConnection

keycloak_connection = KeycloakOpenIDConnection(
                        server_url=KEYCLOAK_BASE,
                        username='mediscus',
                        password='mediscus21',
                        realm_name="master",
                        # user_realm_name="only_if_other_realm_than_master",
                        client_id=KEYCLOAK_CLIENT_ID,
                        client_secret_key=KEYCLOAK_CLIENT_SECRET,
                        verify=False)

keycloak_admin = KeycloakAdmin(connection=keycloak_connection)

@router.post("/register")
def register_primary_user(user_data: dict):
    role = keycloak_admin.get_realm_role("primary_user")
    """ Register a new primary user """
    user_id = keycloak_admin.create_user({
        "username": user_data["username"],
        "email": user_data["email"],
        "firstName": user_data["firstName"],
        "lastName": user_data["lastName"],
        "enabled": True,
        # "attributes": {
        #     "linked_accounts": "[]"
        # }
    })
    print("---------user---------", user_id)
    keycloak_admin.assign_realm_roles(user_id, role)
    return {"message": "Primary user registered successfully"}


@router.post("/add-family-member")
def add_family_member(family_member_data: dict):
    """ Create a family member account linked to the primary user """
    role = keycloak_admin.get_realm_role("secondary_user")
    print("role", role)
    primary_user_id = family_member_data['primary_user_id']
    print("primary_user_id", primary_user_id)
    family_member = keycloak_admin.create_user({
        "username": family_member_data["username"],
        "email": family_member_data["email"],
        "firstName": family_member_data["firstName"],
        "lastName": family_member_data["lastName"],
        "enabled": True,
        "attributes": {
            "primary_account": primary_user_id
        }
    })
    print("family_member", family_member)
    # Assign secondary role
    keycloak_admin.assign_realm_roles(family_member, role)
        
    return {"message": "Family member added successfully"}

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