from fastapi import APIRouter, HTTPException, Depends, Security
from fastapi.security import OAuth2AuthorizationCodeBearer
from pydantic import BaseModel
from typing import Optional
import requests
from dotenv import load_dotenv
import os
import logging

# Load environment variables
load_dotenv()

router = APIRouter()

###################################################################################################
# **🔹 OAUTH2 AUTHORIZATION CODE FLOW (SMART on FHIR COMPLIANT)**
###################################################################################################

oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl=f"{os.getenv('KEYCLOAK_SERVER_URL')}/realms/{os.getenv('KEYCLOAK_REALM')}/protocol/openid-connect/auth",
    tokenUrl=f"{os.getenv('KEYCLOAK_SERVER_URL')}/realms/{os.getenv('KEYCLOAK_REALM')}/protocol/openid-connect/token"
)

###################################################################################################
# **🔹 KEYCLOAK CONFIGURATION**
###################################################################################################

KEYCLOAK_URL = os.getenv("KEYCLOAK_SERVER_URL")
REALM = os.getenv("KEYCLOAK_REALM")
CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID")
CLIENT_SECRET = os.getenv("KEYCLOAK_CLIENT_SECRET")

# Logger Configuration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

###################################################################################################
# **🔹 ADMIN TOKEN MANAGEMENT**
###################################################################################################

def get_admin_token():
    """Obtain an admin token from Keycloak for user management."""
    url = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token"

    data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "client_credentials",
    }

    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    try:
        response = requests.post(url, data=data, headers=headers)
        response_json = response.json()

        if response.status_code != 200:
            raise Exception(f"Failed to obtain admin token: {response_json}")

        return response_json.get("access_token")

    except requests.exceptions.RequestException as e:
        raise Exception(f"Request error: {e}")

###################################################################################################
# **🔹 USER AUTHENTICATION & ROLE VALIDATION**
###################################################################################################

def get_current_user(token: str = Security(oauth2_scheme)):
    """Verify the JWT token, fetch user info, and return user details."""
    headers = {"Authorization": f"Bearer {token}"}
    userinfo_url = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/userinfo"

    response = requests.get(userinfo_url, headers=headers)
    if response.status_code != 200:
        raise HTTPException(status_code=401, detail="Invalid token")

    user_data = response.json()
    user_roles = user_data.get("realm_access", {}).get("roles", [])

    return {
        "id": user_data.get("sub"),
        "email": user_data.get("email"),
        "roles": user_roles,
        "token": token
    }

###################################################################################################
# **🔹 USER REGISTRATION (SIGN-UP)**
###################################################################################################

class SignUpRequest(BaseModel):
    email: str
    password: str
    first_name: str
    last_name: str
    primary_user_id: Optional[str] = None

@router.post("/signup")
def signup(user: SignUpRequest):
    """Registers a **Primary User (Tiger)** in Keycloak."""
    logger.info(f"Signing up user: {user.email}")

    token = get_admin_token()

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/users"

    payload = {
        "username": user.email,
        "email": user.email,
        "firstName": user.first_name,
        "lastName": user.last_name,
        "enabled": True,
        "credentials": [{"type": "password", "value": user.password, "temporary": False}],
        "attributes": {}, 
        "realmRoles": ["primary"]  # Assign primary user role
    }

    response = requests.post(url, json=payload, headers=headers)

    if response.status_code == 201:
        return {"message": "Primary user (Tiger) created successfully"}
    else:
        raise HTTPException(status_code=400, detail="Error creating primary user")

###################################################################################################
# **🔹 FAMILY MEMBER REGISTRATION (CUB)**
###################################################################################################

@router.post("/add-family-member")
def add_family_member(user: SignUpRequest, current_user: dict = Depends(get_current_user)):
    """Registers a **Family Member (Cub)** under a Primary User (Tiger)."""
    
    if "primary" not in current_user["roles"]:
        raise HTTPException(status_code=403, detail="Only primary users can add family members")

    token = get_admin_token()

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/users"

    payload = {
        "username": user.email,
        "email": user.email,
        "firstName": user.first_name,
        "lastName": user.last_name,
        "enabled": True,
        "credentials": [{"type": "password", "value": user.password, "temporary": False}],
        "attributes": {"primary_user_id": current_user["id"]},  
        "realmRoles": ["family"]  # Assign family member role
    }

    response = requests.post(url, json=payload, headers=headers)

    if response.status_code == 201:
        return {"message": "Family member (Cub) created successfully"}
    else:
        raise HTTPException(status_code=400, detail="Error creating family member")

###################################################################################################
# **🔹 USER LOGIN**
###################################################################################################

class LoginRequest(BaseModel):
    username: str
    password: str



@router.post("/login")
def login(user: LoginRequest):
    """Authenticate user with Keycloak."""
    url = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token"
    
    data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "password",
        "username": user.username,
        "password": user.password,
        "scope": "openid profile email"
    }

    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    response = requests.post(url, data=data, headers=headers)

    if response.status_code != 200:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    tokens = response.json()
    access_token = tokens.get("access_token")

    # Fetch user info from Keycloak
    user_info_url = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/userinfo"
    headers = {"Authorization": f"Bearer {access_token}"}
    
    user_info_response = requests.get(user_info_url, headers=headers)

    if user_info_response.status_code == 200:
        return {"access_token": access_token, "user_info": user_info_response.json()}
    else:
        raise HTTPException(status_code=400, detail="Failed to fetch user info")



###################################################################################################
# **🔹 USER LOGOUT**
###################################################################################################

@router.post("/logout")
def logout(current_user: dict = Depends(get_current_user)):
    """Logs out the user by revoking their access token."""
    url = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/logout"

    data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "refresh_token": current_user["token"]
    }

    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    response = requests.post(url, data=data, headers=headers)

    if response.status_code == 204:
        return {"message": "User logged out successfully"}
    else:
        raise HTTPException(status_code=400, detail="Logout failed")

###################################################################################################
# **🔹 DELETE ACCOUNT**
###################################################################################################

@router.delete("/delete-account")
def delete_account(current_user: dict = Depends(get_current_user)):
    """Deletes the authenticated user's account."""
    token = get_admin_token()
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/users/{current_user['id']}"

    response = requests.delete(url, headers=headers)

    if response.status_code == 204:
        return {"message": "User account deleted successfully"}
    else:
        raise HTTPException(status_code=400, detail="Failed to delete account")
