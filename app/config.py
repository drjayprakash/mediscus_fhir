# app/config.py
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

KEYCLOAK_SERVER_URL = os.getenv("KEYCLOAK_SERVER_URL", "https://auth.mediscus.in")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "smart")
KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "smartfhirclient")
KEYCLOAK_CLIENT_SECRET = os.getenv("KEYCLOAK_CLIENT_SECRET")
KEYCLOAK_REDIRECT_URI = os.getenv(
    "KEYCLOAK_REDIRECT_URI", "http://localhost:8000/callback"
)
FHIR_SERVER_BASE = os.getenv("FHIR_SERVER_BASE", "http://156.67.111.202:8080/fhir")


FHIR_CONFIG = {"app_id": "mediscus_app", "api_base": "http://156.67.111.202:8080/fhir"}
