from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
import requests
import os

router = APIRouter()

KEYCLOAK_URL = os.getenv("KEYCLOAK_SERVER_URL")
REALM = os.getenv("KEYCLOAK_REALM")
ADMIN_CLIENT_ID = "admin-cli"
ADMIN_CLIENT_SECRET = os.getenv("KEYCLOAK_CLIENT_SECRET")


class SignUpRequest(BaseModel):
    email: str
    password: str
    first_name: str
    last_name: str


def get_admin_token():
    """Obtain an admin token from Keycloak."""
    url = f"{KEYCLOAK_URL}/realms/master/protocol/openid-connect/token"
    data = {
        "client_id": ADMIN_CLIENT_ID,
        "client_secret": ADMIN_CLIENT_SECRET,
        "grant_type": "client_credentials",
    }
    response = requests.post(url, data=data)
    return response.json()["access_token"]


@router.post("/signup")
def signup(user: SignUpRequest):
    """Register a primary user in Keycloak."""
    token = get_admin_token()

    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/users"

    payload = {
        "username": user.email,
        "email": user.email,
        "firstName": user.firstName,
        "lastName": user.lastName,
        "enabled": True,
        "credentials": [{"type": "password", "value": user.password, "temporary": False}],
        "attributes": {"linked_accounts": "[]"},  # Empty list for family members
    }

    response = requests.post(url, json=payload, headers=headers)
 
    print('response', response)

    if response.status_code == 201:
        return {"message": "User created successfully"}
    else:
        raise HTTPException(status_code=400, detail=response.json())



class LoginRequest(BaseModel):
    username: str
    password: str


@router.post("/login")
def login(user: LoginRequest):
    """Authenticate user with Keycloak."""
    url = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token"
    data = {
        "client_id": "smartfhirclient",
        "client_secret": os.getenv("KEYCLOAK_CLIENT_SECRET"),
        "grant_type": "password",
        "username": user.username,
        "password": user.password,
    }
    
    response = requests.post(url, data=data)

    if response.status_code == 200:
        return response.json()
    else:
        raise HTTPException(status_code=401, detail="Invalid credentials")






class FamilyMemberRequest(BaseModel):
    primary_user_id: str
    family_member_email: str
    first_name: str
    last_name: str
    password: str


@router.post("/add-family-member")
def add_family_member(member: FamilyMemberRequest):
    """Add a family member linked to a primary user."""
    token = get_admin_token()
    
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/users"

    # Create family member user
    payload = {
        "username": member.family_member_email,
        "email": member.family_member_email,
        "firstName": member.first_name,
        "lastName": member.last_name,
        "enabled": True,
        "credentials": [{"type": "password", "value": member.password, "temporary": False}],
    }

    response = requests.post(url, json=payload, headers=headers)
    if response.status_code != 201:
        raise HTTPException(status_code=400, detail="Error creating family member")

    # Retrieve the created user's ID
    new_user_id = response.headers["Location"].split("/")[-1]

    # Update primary user with linked account
    primary_user_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/users/{member.primary_user_id}"
    primary_user_data = requests.get(primary_user_url, headers=headers).json()
    
    linked_accounts = primary_user_data.get("attributes", {}).get("linked_accounts", "[]")
    linked_accounts = eval(linked_accounts)
    linked_accounts.append(new_user_id)

    # Update linked accounts in Keycloak
    requests.put(primary_user_url, json={"attributes": {"linked_accounts": str(linked_accounts)}}, headers=headers)

    return {"message": "Family member added successfully"}





@router.post("/switch-account")
def switch_account(access_token: str, subject: str):
    """Switch accounts using Keycloak Token Exchange."""
    url = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token"
    
    data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "requested_subject": subject,
        "subject_token": access_token,
        "client_id": "smartfhirclient",
        "client_secret": os.getenv("KEYCLOAK_CLIENT_SECRET"),
    }
    
    response = requests.post(url, data=data)

    if response.status_code == 200:
        return response.json()
    else:
        raise HTTPException(status_code=400, detail="Failed to switch account")
