from keycloak import KeycloakAdmin, KeycloakOpenID
import logging
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Keycloak Configuration
KEYCLOAK_SERVER_URL = os.getenv("KEYCLOAK_SERVER_URL")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM")
KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID")
KEYCLOAK_CLIENT_SECRET = os.getenv("KEYCLOAK_CLIENT_SECRET")
KEYCLOAK_REDIRECT_URI = os.getenv("KEYCLOAK_REDIRECT_URI")

# Initialize Logger
logger = logging.getLogger(__name__)

try:
    # Initialize Keycloak Admin API
    # keycloak_admin = KeycloakAdmin(
    #     server_url=KEYCLOAK_SERVER_URL,
    #     username="admin",
    #     password="admin_password",
    #     realm_name=KEYCLOAK_REALM,
    #     verify=True
    # )

    # Initialize Keycloak OpenID Client (for token exchange)
    keycloak_openid = KeycloakOpenID(
        server_url=KEYCLOAK_SERVER_URL,
        client_id=KEYCLOAK_CLIENT_ID,
        realm_name=KEYCLOAK_REALM
    )

    logger.info("✅ Successfully connected to Keycloak")

except Exception as e:
    logger.error(f"❌ Keycloak connection failed: {e}")
