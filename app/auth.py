from fastapi import APIRouter, HTTPException, Depends, Security
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from typing import Optional
import requests
from dotenv import load_dotenv
import os
import json
import logging


load_dotenv()  # This loads environment variables from .env file
router = APIRouter()

# Define the OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


KEYCLOAK_URL = os.getenv("KEYCLOAK_SERVER_URL")
REALM = os.getenv("KEYCLOAK_REALM")
ADMIN_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID")  # Fixed: Ensuring correct variable
ADMIN_CLIENT_SECRET = os.getenv("KEYCLOAK_CLIENT_SECRET")  # Fixed: Ensuring correct variable

def get_admin_token():
    """Obtain an admin token from Keycloak."""
    url = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token"
    
    # Ensure that the variables are correctly loaded
    if not all([KEYCLOAK_URL, REALM, ADMIN_CLIENT_ID, ADMIN_CLIENT_SECRET]):
        raise Exception("One or more required environment variables are missing.")

    data = {
        "client_id": ADMIN_CLIENT_ID,
        "client_secret": ADMIN_CLIENT_SECRET,
        "grant_type": "client_credentials",
    }

    headers = {"Content-Type": "application/x-www-form-urlencoded"}  # Fixed header

    try:
        response = requests.post(url, data=data, headers=headers)
        response_json = response.json()

        # Debugging: Print response details
        print("Keycloak Token Request URL:", url)
        print("Keycloak Token Request Data:", data)
        print("Keycloak Token Response Status Code:", response.status_code)
        print("Keycloak Token Response JSON:", response_json)

        if response.status_code != 200:
            raise Exception(f"Failed to obtain admin token: {response_json}")

        return response_json.get("access_token")

    except requests.exceptions.RequestException as e:
        raise Exception(f"Request error: {e}")
    
###################################################################################################
#role based access control

def get_current_user(token: str = Security(oauth2_scheme)):
    """Verify the JWT token and return user details."""
    headers = {"Authorization": f"Bearer {token}"}
    userinfo_url = f"{KEYCLOAK_SERVER_URL}/realms/{REALM}/protocol/openid-connect/userinfo"
    response = requests.get(userinfo_url, headers=headers)
    if response.status_code != 200:
        raise HTTPException(status_code=401, detail="Invalid token")
    user_data = response.json()
    if "Primary" not in user_data.get("realm_access", {}).get("roles", []):
        raise HTTPException(status_code=403, detail="Forbidden: You don't have access")
    return user_data


##########################################################################################################
#signup

##############################################################################################################




logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SignUpRequest(BaseModel):
    # username: str
    email: str
    password: str
    first_name: str
    last_name: str
    primary_user_id: Optional[str] = None


@router.post("/signup")
def signup(user: SignUpRequest):
    logger.info(f"Signing up user: {user.email}")
    """Register a primary user in Keycloak."""
    token = get_admin_token()  # Obtain admin token

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
        "attributes": {}  # No linked accounts for primary user initially
    }

    response = requests.post(url, json=payload, headers=headers)

    if response.status_code == 201:
        return {"message": "Primary user created successfully"}
    else:
        raise HTTPException(status_code=400, detail="Error creating primary user")


@router.post("/add-family-member")
def add_family_member(user: SignUpRequest):
    """Add a family member linked to a primary user."""
    token = get_admin_token()  # Obtain admin token

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/users"

    # Create family member with primary_user_id as an attribute
    payload = {
        "username": user.email,
        "email": user.email,
        "firstName": user.first_name,
        "lastName": user.last_name,
        "enabled": True,
        "credentials": [{"type": "password", "value": user.password, "temporary": False}],
        "attributes": {"primary_user_id": user.primary_user_id}  # Link to primary user
    }

    response = requests.post(url, json=payload, headers=headers)
    print("response status code", response.status_code)
    print("response headers", response.headers)
    
    if response.status_code != 201:
        print("error json", response.json())
        raise HTTPException(status_code=response.status_code, detail= response.json()['errorMessage'])
    
    family_member_id = response.headers["Location"].split("/")[-1]
    # Retrieve the primary user data
    primary_user_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/users/{user.primary_user_id}"
    primary_user_data = requests.get(primary_user_url, headers=headers).json()

    # Get the existing linked accounts (if any)
    linked_accounts = primary_user_data.get("attributes", {}).get("linked_accounts", [])
    print(linked_accounts)
    print(type(linked_accounts))
    
    # Add the family member to the linked accounts
    linked_accounts.append(family_member_id)
    print("-----------", linked_accounts)
    print(type(linked_accounts))
    # Update the primary user to include the new family member in linked accounts
    update_payload = {
        "attributes": {
            "linked_accounts": linked_accounts
        }
    }
    update_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/users/{user.primary_user_id}"
    response = requests.put(update_url, json=update_payload, headers=headers)

    if response.status_code == 204:
        return {"message": "Family member crerated and linked to primary user successfully"}
    else:
        print("error linking family--", response.json())
        raise HTTPException(status_code=response.status_code, detail=response.json()['errorMessage'])

# Function to fetch all users from Keycloak
def get_user(user_id, token):
    print("get user calling")
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    get_user_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/users/{user_id}"
    user_data = requests.get(get_user_url, headers=headers).json()
    print("user_data", user_data)
    return user_data

@router.get("/get-associated-family-members")
def get_all_family_members(primary_user_id: str):
    """
    Fetch all family members linked to a primary user.
    """
    token = get_admin_token()  # Obtain admin token

    primary_user_data = get_user(primary_user_id, token)

    # Get the existing linked accounts (if any)
    linked_accounts = primary_user_data.get("attributes", {}).get("linked_accounts", [])

    # Filter users who are linked to the primary user
    linked_users = []
    for user_id in linked_accounts:
        userDetails = get_user(user_id, token)
        linked_users.append(userDetails)

    # Return the list of linked family members
    return {"family_members": linked_users}






#######################################################


@router.put("/update-family-member/{member_id}")
def update_family_member(member_id: str, user: SignUpRequest, token: str = Depends(get_admin_token)):
    """Update family member details."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    url = f"{KEYCLOAK_SERVER_URL}/admin/realms/{REALM}/users/{member_id}"
    payload = {
        "firstName": user.first_name,
        "lastName": user.last_name,
        "email": user.email
    }
    response = requests.put(url, json=payload, headers=headers)
    if response.status_code != 204:
        raise HTTPException(status_code=400, detail="Error updating family member")
    return {"message": "Family member updated successfully"}

@router.delete("/delete-family-member/{member_id}")
def delete_family_member(member_id: str, token: str = Depends(get_admin_token)):
    """Delete a family member."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    url = f"{KEYCLOAK_SERVER_URL}/admin/realms/{REALM}/users/{member_id}"
    response = requests.delete(url, headers=headers)
    if response.status_code != 204:
        raise HTTPException(status_code=400, detail="Error deleting family member")
    return {"message": "Family member deleted successfully"}







######################################################################################################################################

class LoginRequest(BaseModel):
    username: str
    password: str

# @router.post("/login")
# def login(user: LoginRequest):
#     """Authenticate user with Keycloak."""
#     url = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token"
    
#     data = {
#         "client_id": os.getenv("KEYCLOAK_CLIENT_ID"),  # Ensure correct client ID
#         "client_secret": os.getenv("KEYCLOAK_CLIENT_SECRET"),  # Ensure correct secret
#         "grant_type": "password",
#         "username": user.username,
#         "password": user.password,
#     }

#     headers = {"Content-Type": "application/x-www-form-urlencoded"}

#     response = requests.post(url, data=data, headers=headers)
    
#     # Debugging: Print response details
#     print("Login Response Status Code:", response.status_code)
#     print("Login Response JSON:", response.json())

#     if response.status_code == 200:
#         return response.json()
#     else:
#         raise HTTPException(status_code=401, detail=response.json())


# first login function is working fine because it only fetches the token and returns it. 
# However, your second function, which also tries to retrieve user info using the /userinfo endpoint, is failing.

@router.post("/login")
def login(user: LoginRequest):
    """Authenticate user with Keycloak."""
    url = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token"
    
    data = {
        "client_id": smartfhir,
        "client_secret": iB9zJEsDxLdzLEF44KUB0xxAmIxsVela,
        "grant_type": "password",
        "username": user.username,
        "password": user.password,
        "scope": "openid profile email"  # Ensure these scopes are requested
    }

    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    response = requests.post(url, data=data, headers=headers)
    
    # Debugging: Print response details
    print("Login Response Status Code:", response.status_code)
    print("Login Response JSON:", response.json())

    if response.status_code != 200:
        raise HTTPException(status_code=401, detail=response.json())

    tokens = response.json()
    access_token = tokens.get("access_token")

    # Fetch user info from Keycloak
    user_info_url = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/userinfo"
    headers = {"Authorization": f"Bearer {access_token}"}
    
    user_info_response = requests.get(user_info_url, headers=headers)

    print("User Info Response Status Code:", user_info_response.status_code)

    if user_info_response.status_code == 200:
        user_data = user_info_response.json()
        return {"access_token": access_token, "user_info": user_data}
    elif user_info_response.status_code == 403:
        print("🔴 ERROR: Access forbidden. Check Keycloak client roles.")
        raise HTTPException(status_code=403, detail="Forbidden: Missing user info permissions")
    else:
        print("🔴 ERROR: Unexpected response when fetching user info")
        raise HTTPException(status_code=400, detail="Failed to fetch user info")


########################################################################################################


#add-family-member
#first login function is working fine because it only fetches the token and returns it. 
#However, your second function, which also tries to retrieve user info using the /userinfo endpoint, is failing.

# @router.post("/add-family-member")
# def add_family_member(member: FamilyMemberRequest):
#     """Add a family member linked to a primary user."""
#     token = get_admin_token()

#     headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
#     url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/users"

#     # Create the family member
#     payload = {
#         "username": member.family_member_email,
#         "email": member.family_member_email,
#         "firstName": member.first_name,
#         "lastName": member.last_name,
#         "enabled": True,
#         "credentials": [{"type": "password", "value": member.password, "temporary": False}],
#         "attributes": {"linked_accounts": "[]"},  # Empty list initially
#     }

#     response = requests.post(url, json=payload, headers=headers)
#     if response.status_code != 201:
#         raise HTTPException(status_code=400, detail="Error creating family member")

#     # Retrieve the created user's ID
#     new_user_id = response.headers["Location"].split("/")[-1]

#     # Assign Family_account Role to New User
#     role_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/users/{new_user_id}/role-mappings/realm"
#     role_payload = [{"name": "Family_account"}]  # Assign Family_account role

#     requests.post(role_url, json=role_payload, headers=headers)

#     # Update primary user's linked_accounts attribute
#     primary_user_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/users/{member.primary_user_id}"
#     primary_user_data = requests.get(primary_user_url, headers=headers).json()

#     linked_accounts = primary_user_data.get("attributes", {}).get("linked_accounts", "[]")
#     linked_accounts = json.loads(linked_accounts) if isinstance(linked_accounts, str) else linked_accounts
#     linked_accounts.append(new_user_id)

#     # Update linked accounts in Keycloak
#     update_payload = {"attributes": {"linked_accounts": json.dumps(linked_accounts)}}
#     requests.put(primary_user_url, json=update_payload, headers=headers)

#     return {"message": "Family member added successfully", "family_member_id": new_user_id}


############################################################################################################################################

# Restrict API Access Based on Role

from fastapi import Security, Depends
from fastapi.security import OAuth2PasswordBearer

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_current_user(token: str = Security(oauth2_scheme)):
    """Verify the JWT token and return user details."""
    headers = {"Authorization": f"Bearer {token}"}
    userinfo_url = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/userinfo"
    
    response = requests.get(userinfo_url, headers=headers)
    if response.status_code != 200:
        raise HTTPException(status_code=401, detail="Invalid token")

    return response.json()

# Example of protecting an endpoint
@router.get("/secure-data")
def get_secure_data(user: dict = Depends(get_current_user)):
    """Only Primary users can access this."""
    if "Primary" not in user.get("realm_access", {}).get("roles", []):
        raise HTTPException(status_code=403, detail="Forbidden: You don't have access")

    return {"message": "Secure data accessed successfully!"}



#############################################################################################################################################




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

