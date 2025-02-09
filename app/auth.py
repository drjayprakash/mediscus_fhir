from fastapi import APIRouter, HTTPException, Depends, Security
from fastapi.security import OAuth2AuthorizationCodeBearer
from pydantic import BaseModel
from typing import Optional
import requests
from dotenv import load_dotenv
import os
import logging
from authlib.jose import jwt, JoseError

# Logger Configuration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

router = APIRouter()

###################################################################################################
# **🔹 KEYCLOAK CONFIGURATION**
###################################################################################################

KEYCLOAK_URL = os.getenv("KEYCLOAK_SERVER_URL")
REALM = os.getenv("KEYCLOAK_REALM")
CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID")
CLIENT_SECRET = os.getenv("KEYCLOAK_CLIENT_SECRET")

###################################################################################################
# **🔹 OAUTH2 AUTHORIZATION CODE FLOW (SMART on FHIR COMPLIANT)**
###################################################################################################

oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl=f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/auth",
    tokenUrl=f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token"
)

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

# Fetch Keycloak Public Key
def get_keycloak_public_key():
    url = f"{KEYCLOAK_URL}/realms/{REALM}"
    response = requests.get(url)
    if response.status_code != 200:
        raise Exception("Failed to get Keycloak public key")

    public_key = response.json().get("public_key")
    print("public key", public_key)
    return f"-----BEGIN PUBLIC KEY-----\n{public_key}\n-----END PUBLIC KEY-----"

def get_current_user(token: str = Security(oauth2_scheme)):
    """Verify the JWT token, fetch user info, and return user details."""
    # print("token", token)
    try:
        decoded_token = jwt.decode(token, key=get_keycloak_public_key(), claims_options={"verify": False})
        print("decoded_token----------", decoded_token)
    # headers = {"Authorization": f"Bearer {token}"}
    # userinfo_url = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/userinfo"
    # response = requests.get(userinfo_url, headers=headers)
    # if response.status_code != 200:
    #     raise HTTPException(status_code=401, detail="Invalid token")
    # user_data = response.json()
    # print("user_data", user_data) 
        return {
            "sub": decoded_token.get("sub"),
            "email": decoded_token.get("email"),
            "email_verified": decoded_token.get("email_verified"),
            "name": decoded_token.get("name"),
            "preferred_username": decoded_token.get("preferred_username"),
            "given_name": decoded_token.get("given_name"),
            "family_name": decoded_token.get("family_name"),
            "roles": decoded_token.get("realm_access", {}).get("roles", []),
            # "token": token
        }
    except JoseError as e:
        raise HTTPException(status_code=401, detail=f"Invalid or expired token: {str(e)}")
    # except jwt.InvalidTokenError:
    #     raise HTTPException(status_code=401, detail="Invalid token")

###################################################################################################
# ** USER ROLE MAPPING **
###################################################################################################

def assign_realm_role(user_id, role_name, headers):
    """Assign a realm role to a user."""
    
    # Fetch role details
    role_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/roles/{role_name}"
    # headers = {"Authorization": f"Bearer {get_admin_token()}", "Content-Type": "application/json"}
    role_response = requests.get(role_url, headers=headers)
    
    if role_response.status_code != 200:
        print("Role not found:", role_response.json())
        return False

    role_data = role_response.json()

    # Assign the role to the user
    assign_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/users/{user_id}/role-mappings/realm"
    response = requests.post(assign_url, json=[role_data], headers=headers)

    if response.status_code == 204:
        print(f"Role '{role_name}' assigned successfully!")
        return True
    else:
        print("Error assigning role:", response.json())
        raise Exception("Error assigning role")
    
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

    headers = {
        "Authorization": f"Bearer {get_admin_token()}",
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
        # "realmRoles": ["primary"]  # Assign primary user role
    }

    response = requests.post(url, json=payload, headers=headers)

    if response.status_code == 201:
        user_id = response.headers.get("Location").split("/")[-1]
        assign_realm_role(user_id, "primary", headers)
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

    headers = {
        "Authorization": f"Bearer {get_admin_token()}",
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
        "attributes": {"primary_user_id": current_user["sub"]},  
        # "realmRoles": ["family"]  # Assign family member role
    }

    response = requests.post(url, json=payload, headers=headers)
    print(response.text)
    if response.status_code == 201:
        user_id = response.headers.get("Location").split("/")[-1]
        assign_realm_role(user_id, "family", headers)
        return {"message": "Family member (Cub) created successfully"}
    else:
        raise HTTPException(status_code=400, detail="Error creating family member")

###################################################################################################
# **USER LOGIN**
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
    print("tokens", tokens)
    access_token = tokens.get("access_token")
    # # Fetch user info from Keycloak
    # user_info_url = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/userinfo"
    # headers = {"Authorization": f"Bearer {access_token}"}
    
    # user_info_response = requests.get(user_info_url, headers=headers)
    # user_info_response = get_current_user(access_token)
    # if user_info_response.status_code == 200:
    #     tokens['user_info'] = user_info_response.json()
    #     return tokens
    # else:
    #     raise HTTPException(status_code=400, detail="Failed to fetch user info")
    tokens['user_info'] = get_current_user(access_token)

    return tokens
    

###################################################################################################
# **🔹 USER LOGOUT**
###################################################################################################

class LogoutRequest(BaseModel):
    refresh_token: str
    
@router.post("/logout")
def logout(user_token: LogoutRequest, current_user: dict = Depends(get_current_user)):

    """Logs out the user by revoking their access token."""
    url = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/logout"
    data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "refresh_token": user_token.refresh_token
    }

    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    response = requests.post(url, data=data, headers=headers)
    print("response", response.status_code)
    print("response", response.text)
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
    print("current_user", current_user)
    headers = {
        "Authorization": f"Bearer {get_admin_token()}",
        "Content-Type": "application/json"
    }
    
    url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/users/{current_user['sub']}"

    response = requests.delete(url, headers=headers)

    if response.status_code == 204:
        return {"message": "User account deleted successfully"}
    else:
        raise HTTPException(status_code=400, detail="Failed to delete account")

###################################################################################################
# ** GET ASSOCIATED FAMILY MEMBERS**
###################################################################################################

@router.get("/get-associated-family-members")
def get_associated_family_members(current_user: dict = Depends(get_current_user)):
    """
    Fetch all family members linked to a primary user.
    """
    url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/users"
    headers = {"Authorization": f"Bearer {get_admin_token()}"}
    
    # Search for users where primary_user_id matches
    params = {"q": f"primary_user_id:{current_user['sub']}"}
    response = requests.get(url, headers=headers, params=params)

    if response.status_code == 200:
        return response.json()
    else:
        raise HTTPException(status_code=400, detail="Failed to fetch family members")