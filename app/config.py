
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Ensure all required variables are present
KEYCLOAK_BASE = os.getenv("KEYCLOAK_BASE")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM")
KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID")
KEYCLOAK_CLIENT_SECRET = os.getenv("KEYCLOAK_CLIENT_SECRET")
KEYCLOAK_REDIRECT_URI = os.getenv("KEYCLOAK_REDIRECT_URI")
FHIR_BASE_URL = os.getenv("FHIR_BASE_URL")
FHIR_SERVER_BASE = os.getenv("FHIR_BASE_URL")  # Or use correct variable name


# Debugging: Print environment values to verify they are loaded
print("✅ Keycloak Base URL:", KEYCLOAK_BASE)
print("✅ Keycloak Realm:", KEYCLOAK_REALM)
print("✅ Keycloak Client ID:", KEYCLOAK_CLIENT_ID)
print("✅ Keycloak Redirect URI:", KEYCLOAK_REDIRECT_URI)
